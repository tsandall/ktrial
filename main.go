package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/dependencies"
	"github.com/spf13/cobra"
	admissionreview "k8s.io/api/admission/v1beta1"
	admission "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

type params struct {
	configAccess clientcmd.ConfigAccess
	prefix       string
	format       string
	mutating     bool
}

var defaultKubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")

func main() {

	var params params

	cmd := cobra.Command{
		Use:   fmt.Sprintf("%v <file-1> [<file-2> [...]]", os.Args[0]),
		Short: "Trial an OPA admission control policy.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(cmd, args, params); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	pathOpts := clientcmd.NewDefaultPathOptions()

	cmd.PersistentFlags().StringVar(&pathOpts.LoadingRules.ExplicitPath, pathOpts.ExplicitFileFlag, pathOpts.LoadingRules.ExplicitPath, "use a particular kubeconfig file")
	cmd.Flags().StringVarP(&params.prefix, "prefix", "p", os.Getenv("USER"), "set namespace and webhook name prefix")
	cmd.Flags().BoolVarP(&params.mutating, "mutating", "m", false, "register as a mutating webhook instead of a validating webhook")

	params.configAccess = pathOpts

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string, params params) (err error) {

	startingConfig, err := params.configAccess.GetStartingConfig()
	if err != nil {
		return err
	}

	fmt.Printf("Using context %q\n", startingConfig.CurrentContext)

	config, err := clientcmd.NewDefaultClientConfig(*startingConfig, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	var env environment

	opaNsName := params.prefix + "-opa"
	testNsName := params.prefix + "-opa-test"
	webhookName := params.prefix + "-opa-webhook"
	opaClusterRoleBindingName := params.prefix + "-opa-viewer"

	cleanupMsg := func() {
		fmt.Println()
		fmt.Printf("# Run the following command to disable webhook:\n")

		var webhookKind string

		if params.mutating {
			webhookKind = "mutatingwebhookconfigurations"
		} else {
			webhookKind = "validatingwebhookconfigurations"
		}

		fmt.Printf("kubectl delete %v/%v\n", webhookKind, webhookName)
		fmt.Println()
		fmt.Printf("# Run the following commands to cleanup:\n")
		fmt.Printf("kubectl delete namespaces/%v namespaces/%v\n", opaNsName, testNsName)
		fmt.Printf("kubectl delete clusterrolebinding/%v\n", opaClusterRoleBindingName)
	}

	defer func() {
		cleanupMsg()
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Printf("signal: %v\n", sig)
		cleanupMsg()
		os.Exit(1)
	}()

	env, err = deployAdmissionController(clientset, opaNsName, testNsName, webhookName, opaClusterRoleBindingName, params.mutating, args)
	if err != nil {
		return err
	}

	fmt.Printf("Reading decisions from pod %q...\n", env.Pod.Name)

	req := clientset.CoreV1().Pods(env.Pod.Namespace).GetLogs(env.Pod.Name, &v1.PodLogOptions{Follow: true, Container: "opa"})
	readCloser, err := req.Stream()
	if err != nil {
		return err
	}

	defer readCloser.Close()

	decoder := &decisionDecoder{
		Decoder: json.NewDecoder(readCloser),
	}

	for {
		decision, err := decoder.Decode()
		if err != nil {
			return err
		}

		fmt.Println(strings.Repeat("-", 80))

		if err := printJSON(decision); err != nil {
			return err
		}
	}
}

func printJSON(decision *decision) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(decision)
}

type environment struct {
	TestNamespace     *v1.Namespace
	OPANamespace      *v1.Namespace
	ValidatingWebhook *admission.ValidatingWebhookConfiguration
	MutatingWebhook   *admission.MutatingWebhookConfiguration
	Pod               *v1.Pod
}

func deployAdmissionController(clientset *kubernetes.Clientset, opaNsName, testNsName, webhookName, opaClusterRoleBindingName string, mutating bool, args []string) (environment, error) {

	var env environment
	var err error

	env.OPANamespace, err = applyNamespace(clientset, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: opaNsName,
		},
	})
	if err != nil {
		return env, err
	}

	env.TestNamespace, err = applyNamespace(clientset, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNsName,
			Labels: map[string]string{
				"name": testNsName,
			},
		},
	})
	if err != nil {
		return env, err
	}

	svc, err := applyService(clientset, env.OPANamespace.Name, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "opa",
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{"app": "opa"},
			Ports: []v1.ServicePort{
				{Name: "https", Protocol: v1.ProtocolTCP, Port: 443, TargetPort: intstr.FromInt(443)},
			},
		},
	})
	if err != nil {
		return env, err
	}

	caCert, cert, key, err := generateSelfSignedCertAndKey(env.OPANamespace.Name)
	if err != nil {
		return env, err
	}

	_, err = applySecret(clientset, env.OPANamespace.Name, &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "opa-cert",
		},
		Data: map[string][]byte{
			"tls.key": key,
			"tls.crt": cert,
		},
	})
	if err != nil {
		return env, err
	}

	files, err := getFiles(args)
	if err != nil {
		log.Fatal(err)
	}

	policy, err := applySecret(clientset, env.OPANamespace.Name, &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "opa-policy",
		},
		Data: files,
	})
	if err != nil {
		return env, err
	}

	resources, err := getKubernetesResourceDependencies(files)
	if err != nil {
		return env, err
	}

	resourceList, err := clientset.Discovery().ServerResources()
	if err != nil {
		return env, err
	}

	replicate, replicateCluster := getKubemgmtReplicateFlagSets(resourceList, resources)
	fmt.Println("Detected namespace-scoped resources :", replicate)
	fmt.Println("Detected cluster-scoped resources   :", replicateCluster)

	containers := []v1.Container{
		{
			Name:  "opa",
			Image: "openpolicyagent/opa:0.13.0",
			Args: []string{
				"run",
				"--log-level=debug",
				"--log-format=json",
				"--server",
				"--addr=0.0.0.0:443",
				"--addr=http://127.0.0.1:8181",
				"--tls-cert-file=/certs/tls.crt",
				"--tls-private-key-file=/certs/tls.key",
				"--ignore=.*",
				"--set=decision_logs.console=true",
				"/policies",
			},
			VolumeMounts: []v1.VolumeMount{
				{Name: "opa-policy", ReadOnly: true, MountPath: "/policies"},
				{Name: "opa-cert", ReadOnly: true, MountPath: "/certs"},
			},
		},
	}

	if len(replicate) > 0 || len(replicateCluster) > 0 {
		args := []string{"--enable-policies=false"}
		for _, r := range replicate {
			args = append(args, "--replicate="+r)
		}
		for _, r := range replicateCluster {
			args = append(args, "--replicate-cluster="+r)
		}
		containers = append(containers, v1.Container{
			Name:  "kube-mgmt",
			Image: "openpolicyagent/kube-mgmt:0.8",
			Args:  args,
		})

		_, err = applyRoleBinding(clientset, &rbac.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: opaClusterRoleBindingName,
			},
			RoleRef: rbac.RoleRef{
				Kind:     "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     "view",
			},
			Subjects: []rbac.Subject{
				{
					Kind:     "Group",
					APIGroup: "rbac.authorization.k8s.io",
					Name:     "system:serviceaccounts:" + env.OPANamespace.Name,
				},
			},
		})
		if err != nil {
			return env, err
		}
	}

	env.Pod, err = applyPod(clientset, env.OPANamespace.Name, &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "opa",
			Labels: map[string]string{"app": "opa"},
		},
		Spec: v1.PodSpec{
			Containers: containers,
			Volumes: []v1.Volume{
				{
					Name: "opa-policy",
					VolumeSource: v1.VolumeSource{
						Secret: &v1.SecretVolumeSource{
							SecretName: policy.Name,
						},
					},
				},
				{
					Name: "opa-cert",
					VolumeSource: v1.VolumeSource{
						Secret: &v1.SecretVolumeSource{
							SecretName: "opa-cert",
						},
					},
				},
			},
		},
	})
	if err != nil {
		return env, err
	}

	failurePolicy := admission.Fail

	webhook := admission.Webhook{
		Name: "admission.openpolicyagent.org",
		ClientConfig: admission.WebhookClientConfig{
			Service: &admission.ServiceReference{
				Namespace: svc.Namespace,
				Name:      svc.Name,
			},
			CABundle: caCert,
		},
		Rules: []admission.RuleWithOperations{
			{
				Operations: []admission.OperationType{admission.OperationAll},
				Rule: admission.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*"},
				},
			},
		},
		FailurePolicy: &failurePolicy,
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"name": env.TestNamespace.Name,
			},
		},
	}

	if !mutating {
		env.ValidatingWebhook, err = applyValidatingWebhookConfiguration(clientset, &admission.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookName,
			},
			Webhooks: []admission.Webhook{
				webhook,
			},
		})
		if err != nil {
			return env, err
		}
	} else {
		env.MutatingWebhook, err = applyMutatingWebhookConfiguration(clientset, &admission.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookName,
			},
			Webhooks: []admission.Webhook{
				webhook,
			},
		})
		if err != nil {
			return env, err
		}
	}

	if err := waitForRunning(clientset, env.Pod); err != nil {
		return env, err
	}

	return env, nil
}

func gvkToString(gvk metav1.GroupVersionKind) string {
	parts := []string{}
	if gvk.Group != "" {
		parts = append(parts, gvk.Group)
	}
	parts = append(parts, gvk.Version)
	parts = append(parts, gvk.Kind)
	return strings.Join(parts, "/")
}

type decisionDecoder struct {
	Decoder *json.Decoder
}

type decision struct {
	Input   admissionreview.AdmissionReview `json:"input"`
	Result  admissionreview.AdmissionReview `json:"result"`
	Metrics map[string]interface{}          `json:"metrics"`
}

func (d *decisionDecoder) Decode() (*decision, error) {

	for {

		var record struct {
			decision
			Msg string `json:"msg"`
		}

		if err := d.Decoder.Decode(&record); err != nil {
			return nil, err
		}

		if record.Msg != "Decision Log" {
			continue
		}

		return &record.decision, nil
	}
}

func getKubemgmtReplicateFlagSets(resourceLists []*metav1.APIResourceList, resources map[string]struct{}) (replicate []string, replicateCluster []string) {
	for r := range resources {
		if path, cluster, ok := getKubemgmtReplicateFlag(resourceLists, r); ok && !cluster {
			replicate = append(replicate, path)
		} else if ok && cluster {
			replicateCluster = append(replicateCluster, path)
		}
	}
	return
}

func getKubemgmtReplicateFlag(resourceLists []*metav1.APIResourceList, r string) (string, bool, bool) {
	for _, list := range resourceLists {
		for _, apiResource := range list.APIResources {
			if apiResource.Name == r {
				return list.GroupVersion + "/" + r, !apiResource.Namespaced, true
			}
		}
	}
	return "", false, false
}

func getKubernetesResourceDependencies(files map[string][]byte) (map[string]struct{}, error) {

	modules := make(map[string]*ast.Module, len(files))

	for filename, bs := range files {
		var err error
		modules[filename], err = ast.ParseModule(filename, string(bs))
		if err != nil {
			return nil, err
		}
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, compiler.Errors
	}

	kubePrefix := ast.MustParseRef("data.kubernetes")
	admissionPrefix := ast.MustParseRef("data.kubernetes.admission")

	result := map[string]struct{}{}

	for _, module := range compiler.Modules {
		refs, err := dependencies.Base(compiler, module)
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			if ref.HasPrefix(kubePrefix) && !ref.HasPrefix(admissionPrefix) {
				if len(ref) >= 3 {
					str, ok := ref[2].Value.(ast.String)
					if !ok {
						continue
					}
					result[string(str)] = struct{}{}
				}
			}
		}
	}

	return result, nil
}

func getFiles(args []string) (map[string][]byte, error) {
	files := map[string][]byte{}
	modules := map[string]*ast.Module{}
	generateDefaultDecision := true
	systemPackage := ast.MustParsePackage("package system")
	for _, filename := range args {
		var err error
		ext := filepath.Ext(filename)
		switch ext {
		case ".json", ".yaml", ".yml":
			files[filename], err = ioutil.ReadFile(filename)
			if err != nil {
				return nil, err
			}
		case ".rego":
			files[filename], err = ioutil.ReadFile(filename)
			if err != nil {
				return nil, err
			}
			module, err := ast.ParseModule(filename, string(files[filename]))
			if err != nil {
				return nil, err
			}
			modules[filename] = module
			if generateDefaultDecision {
				generateDefaultDecision = !containsMainRule(systemPackage, module)
			}
		default:
			return nil, fmt.Errorf("unsupported file extension %q", ext)
		}
	}
	if generateDefaultDecision {
		files["default-system-main.rego"] = []byte(generateBoilerplate(systemPackage, modules).String())
	}
	for filename, bs := range files {
		delete(files, filename)
		files[sanitizeFilename(filename)] = bs
	}
	return files, nil
}

func sanitizeFilename(filename string) string {
	// TODO(tsandall): this ought to handle other non-alphanumeric/-/_/. characters.
	return strings.Replace(filename, "/", "_", -1)
}

func containsMainRule(systemPackage *ast.Package, module *ast.Module) bool {
	if !module.Package.Equal(systemPackage) {
		return false
	}
	for _, rule := range module.Rules {
		if rule.Head.Name.Equal(ast.Var("main")) {
			return true
		}
	}
	return false
}
func generateBoilerplate(systemPackage *ast.Package, modules map[string]*ast.Module) *ast.Module {
	rules := []*ast.Rule{}
	for _, module := range modules {
		if !module.Package.Equal(systemPackage) {
			for _, rule := range module.Rules {
				if rule.Head.Name.Equal(ast.Var("deny")) {
					rules = append(rules, &ast.Rule{
						Head: ast.NewHead(ast.Var("deny"), ast.VarTerm("info")),
						Body: ast.NewBody(ast.NewExpr(ast.NewTerm(rule.Path().Append(ast.VarTerm("info"))))),
					})
				}
			}
		}
	}
	rules = append(rules, ast.MustParseRule(`main = {"kind": "AdmissionReview", "apiVersion": "admission.k8s.io/v1beta1", "response": response} { true }`))
	rules = append(rules, ast.MustParseRule(`default response = {"allowed": true}`))
	rules = append(rules, ast.MustParseRule(`deny["null"] { false }`))
	rules = append(rules, ast.MustParseRule(`response = {"allowed": false, "status": {"reason": msg}} { msg := concat(", ", deny); msg != "" }`))
	return &ast.Module{
		Package: systemPackage,
		Rules:   rules,
	}
}

func applyNamespace(clientset *kubernetes.Clientset, obj *v1.Namespace) (*v1.Namespace, error) {
	fmt.Printf("Declaring namespace %q\n", obj.Name)
	ns, err := clientset.CoreV1().Namespaces().Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		ns, err = clientset.CoreV1().Namespaces().Update(obj)
	}
	return ns, err
}

func applyService(clientset *kubernetes.Clientset, namespace string, obj *v1.Service) (*v1.Service, error) {
	fmt.Printf("Declaring service %q\n", obj.Name)
	svc, err := clientset.CoreV1().Services(namespace).Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := clientset.CoreV1().Services(namespace).Delete(obj.Name, nil); err != nil {
			return nil, err
		}
		svc, err = clientset.CoreV1().Services(namespace).Create(obj)
	}
	return svc, err
}

func applySecret(clientset *kubernetes.Clientset, namespace string, obj *v1.Secret) (*v1.Secret, error) {
	fmt.Printf("Declaring secret %q\n", obj.Name)
	secret, err := clientset.CoreV1().Secrets(namespace).Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := clientset.CoreV1().Secrets(namespace).Delete(obj.Name, nil); err != nil {
			return nil, err
		}
		secret, err = clientset.CoreV1().Secrets(namespace).Create(obj)
	}
	return secret, err
}

func applyPod(clientset *kubernetes.Clientset, namespace string, obj *v1.Pod) (*v1.Pod, error) {
	fmt.Printf("Declaring pod %q (this may take a few seconds...)\n", obj.Name)
	pod, err := clientset.CoreV1().Pods(namespace).Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := clientset.CoreV1().Pods(namespace).Delete(obj.Name, nil); err != nil {
			return nil, err
		}
		gone := false
		for !gone {
			_, err := clientset.CoreV1().Pods(namespace).Get(obj.Name, metav1.GetOptions{})
			if err != nil {
				if !errors.IsNotFound(err) {
					return nil, err
				}
				gone = true
			}
			time.Sleep(10 * time.Millisecond)
		}
		pod, err = clientset.CoreV1().Pods(namespace).Create(obj)
	}
	return pod, err
}

func applyValidatingWebhookConfiguration(clientset *kubernetes.Clientset, obj *admission.ValidatingWebhookConfiguration) (*admission.ValidatingWebhookConfiguration, error) {
	fmt.Printf("Declaring validatingwebhookconfiguration %q\n", obj.Name)
	reg, err := clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Delete(obj.Name, nil); err != nil {
			return nil, err
		}
		reg, err = clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Create(obj)
	}
	return reg, err
}

func applyMutatingWebhookConfiguration(clientset *kubernetes.Clientset, obj *admission.MutatingWebhookConfiguration) (*admission.MutatingWebhookConfiguration, error) {
	fmt.Printf("Declaring mutatingwebhookconfiguration %q\n", obj.Name)
	reg, err := clientset.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := clientset.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Delete(obj.Name, nil); err != nil {
			return nil, err
		}
		reg, err = clientset.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Create(obj)
	}
	return reg, err
}

func applyRoleBinding(clientset *kubernetes.Clientset, obj *rbac.ClusterRoleBinding) (*rbac.ClusterRoleBinding, error) {
	fmt.Printf("Declaring clusterrolebinding %q\n", obj.Name)
	rb, err := clientset.RbacV1().ClusterRoleBindings().Create(obj)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		if err := clientset.RbacV1().ClusterRoleBindings().Delete(obj.Name, nil); err != nil {
			return nil, err
		}
		rb, err = clientset.RbacV1().ClusterRoleBindings().Create(obj)
	}
	return rb, err
}

func waitForRunning(clientset *kubernetes.Clientset, pod *v1.Pod) error {
	for {
		resp, err := clientset.CoreV1().Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		switch resp.Status.Phase {
		case v1.PodRunning:
			return nil
		case v1.PodPending:
			time.Sleep(10 * time.Millisecond)
			break
		default:
			return fmt.Errorf("pod %q in bad phase %q", pod.Name, resp.Status.Phase)
		}
	}
}

const (
	numBits        = 2048
	org            = "opa"
	webhookService = "opa.%s.svc"
)

func generateSelfSignedCertAndKey(namespace string) ([]byte, []byte, []byte, error) {
	priv, err := rsa.GenerateKey(crypto_rand.Reader, numBits)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, fmt.Errorf("Failed to create private key: %s", err.Error())
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 10000) // good for 10,000 days

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		DNSNames:              []string{fmt.Sprintf(webhookService, namespace)},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, fmt.Errorf("Failed to create certificate: %s", err.Error())
	}

	// var certOut *bytes.Buffer
	certOut := &bytes.Buffer{}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	keyOut := &bytes.Buffer{}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	return certOut.Bytes(), certOut.Bytes(), keyOut.Bytes(), nil
}
