package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

type testSecretsManagerClient struct {
	getRsp []*secretsmanager.GetSecretValueOutput
	getCnt int
}

func (m *testSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.getCnt >= len(m.getRsp) {
		panic("unexpected GetSecretValue")
	}
	r := m.getRsp[m.getCnt]
	m.getCnt++
	return r, nil
}

func (m *testSecretsManagerClient) DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	panic("unexpected DescribeSecret")
}

func smDescriptor(t *testing.T, mountDir string, jmes []JMESPathEntry) *SecretDescriptor {
	t.Helper()
	return &SecretDescriptor{
		ObjectName: "testsecret",
		ObjectType: "secretsmanager",
		mountDir:   mountDir,
		JMESPath:   jmes,
	}
}

func TestSecretsManagerJMES_invalidSyntaxDoesNotTryFailoverRegion(t *testing.T) {
	dir := t.TempDir()
	d := smDescriptor(t, dir, []JMESPathEntry{{Path: ".badpath", ObjectAlias: "x"}})
	primary := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"a":"b"}`), VersionId: aws.String("1")},
		},
	}
	failover := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"a":"b"}`), VersionId: aws.String("2")},
		},
	}
	p := NewSecretsManagerProviderWithClients(
		SecretsManagerClient{Region: "r1", Client: primary},
		SecretsManagerClient{Region: "r2", Client: failover, IsFailover: true},
	)
	_, err := p.GetSecretValues(context.Background(), []*SecretDescriptor{d}, map[string]*v1alpha1.ObjectVersion{})
	if err == nil {
		t.Fatal("expected error")
	}
	var syn *JMESPathInvalidSyntaxError
	if !errors.As(err, &syn) {
		t.Fatalf("want JMESPathInvalidSyntaxError, got %T: %v", err, err)
	}
	if primary.getCnt != 1 {
		t.Fatalf("primary GetSecretValue calls = %d, want 1", primary.getCnt)
	}
	if failover.getCnt != 0 {
		t.Fatalf("failover GetSecretValue calls = %d, want 0 (fail fast)", failover.getCnt)
	}
}

func TestSecretsManagerJMES_noMatchAllRegionsReturnsSpecificError(t *testing.T) {
	dir := t.TempDir()
	d := smDescriptor(t, dir, []JMESPathEntry{{Path: "missing", ObjectAlias: "alias1"}})
	c1 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"hello":"world"}`), VersionId: aws.String("1")},
		},
	}
	c2 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"hello":"world"}`), VersionId: aws.String("2")},
		},
	}
	p := NewSecretsManagerProviderWithClients(
		SecretsManagerClient{Region: "r1", Client: c1},
		SecretsManagerClient{Region: "r2", Client: c2, IsFailover: true},
	)
	_, err := p.GetSecretValues(context.Background(), []*SecretDescriptor{d}, map[string]*v1alpha1.ObjectVersion{})
	if err == nil {
		t.Fatal("expected error")
	}
	var nm *JMESPathNoMatchError
	if !errors.As(err, &nm) {
		t.Fatalf("want JMESPathNoMatchError, got %T: %v", err, err)
	}
	if c1.getCnt != 1 || c2.getCnt != 1 {
		t.Fatalf("expected one GetSecretValue per region, got %d and %d", c1.getCnt, c2.getCnt)
	}
}

func TestSecretsManagerJMES_noMatchThenFailoverSucceeds(t *testing.T) {
	dir := t.TempDir()
	d := smDescriptor(t, dir, []JMESPathEntry{{Path: "want", ObjectAlias: "wantVal"}})
	c1 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"only":"here"}`), VersionId: aws.String("1")},
		},
	}
	c2 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"want":"found"}`), VersionId: aws.String("2")},
		},
	}
	p := NewSecretsManagerProviderWithClients(
		SecretsManagerClient{Region: "r1", Client: c1},
		SecretsManagerClient{Region: "r2", Client: c2, IsFailover: true},
	)
	cur := map[string]*v1alpha1.ObjectVersion{}
	vals, err := p.GetSecretValues(context.Background(), []*SecretDescriptor{d}, cur)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 2 {
		t.Fatalf("len(vals)=%d, want 2 (parent + jmes)", len(vals))
	}
	if c1.getCnt != 1 || c2.getCnt != 1 {
		t.Fatalf("expected one GetSecretValue per region, got %d and %d", c1.getCnt, c2.getCnt)
	}
	found := false
	for _, v := range vals {
		if v.Descriptor.ObjectAlias == "wantVal" && string(v.Value) == "found" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jmes alias value, got %#v", vals)
	}
}

func TestSecretsManagerJMES_invalidJSONThenFailoverSucceeds(t *testing.T) {
	dir := t.TempDir()
	d := smDescriptor(t, dir, []JMESPathEntry{{Path: "k", ObjectAlias: "outK"}})
	c1 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`not valid json`), VersionId: aws.String("1")},
		},
	}
	c2 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"k":"from-region-2"}`), VersionId: aws.String("2")},
		},
	}
	p := NewSecretsManagerProviderWithClients(
		SecretsManagerClient{Region: "r1", Client: c1},
		SecretsManagerClient{Region: "r2", Client: c2, IsFailover: true},
	)
	cur := map[string]*v1alpha1.ObjectVersion{}
	vals, err := p.GetSecretValues(context.Background(), []*SecretDescriptor{d}, cur)
	if err != nil {
		t.Fatal(err)
	}
	if c1.getCnt != 1 || c2.getCnt != 1 {
		t.Fatalf("expected one GetSecretValue per region, got %d and %d", c1.getCnt, c2.getCnt)
	}
	found := false
	for _, v := range vals {
		if v.Descriptor.ObjectAlias == "outK" && string(v.Value) == "from-region-2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jmes value from failover, got %#v", vals)
	}
}

func TestSecretsManagerJMES_wrongResultTypeThenFailoverSucceeds(t *testing.T) {
	dir := t.TempDir()
	d := smDescriptor(t, dir, []JMESPathEntry{{Path: "username", ObjectAlias: "userOut"}})
	c1 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"username":3}`), VersionId: aws.String("1")},
		},
	}
	c2 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`{"username":"string-in-r2"}`), VersionId: aws.String("2")},
		},
	}
	p := NewSecretsManagerProviderWithClients(
		SecretsManagerClient{Region: "r1", Client: c1},
		SecretsManagerClient{Region: "r2", Client: c2, IsFailover: true},
	)
	cur := map[string]*v1alpha1.ObjectVersion{}
	vals, err := p.GetSecretValues(context.Background(), []*SecretDescriptor{d}, cur)
	if err != nil {
		t.Fatal(err)
	}
	if c1.getCnt != 1 || c2.getCnt != 1 {
		t.Fatalf("expected one GetSecretValue per region, got %d and %d", c1.getCnt, c2.getCnt)
	}
	found := false
	for _, v := range vals {
		if v.Descriptor.ObjectAlias == "userOut" && string(v.Value) == "string-in-r2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jmes string from failover, got %#v", vals)
	}
}

func TestSecretsManagerJMES_invalidJSONAllRegionsReturnsSpecificError(t *testing.T) {
	dir := t.TempDir()
	d := smDescriptor(t, dir, []JMESPathEntry{{Path: "k", ObjectAlias: "x"}})
	c1 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`plain`), VersionId: aws.String("1")},
		},
	}
	c2 := &testSecretsManagerClient{
		getRsp: []*secretsmanager.GetSecretValueOutput{
			{SecretString: aws.String(`also-not-json`), VersionId: aws.String("2")},
		},
	}
	p := NewSecretsManagerProviderWithClients(
		SecretsManagerClient{Region: "r1", Client: c1},
		SecretsManagerClient{Region: "r2", Client: c2, IsFailover: true},
	)
	_, err := p.GetSecretValues(context.Background(), []*SecretDescriptor{d}, map[string]*v1alpha1.ObjectVersion{})
	if err == nil {
		t.Fatal("expected error")
	}
	var je *JMESPathInvalidJSONError
	if !errors.As(err, &je) {
		t.Fatalf("want JMESPathInvalidJSONError, got %T: %v", err, err)
	}
}
