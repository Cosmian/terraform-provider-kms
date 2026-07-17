// Package provider implements the Terraform Plugin Framework provider for Cosmian KMS.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
	"github.com/cosmian/terraform-provider-kms/internal/datasources"
	"github.com/cosmian/terraform-provider-kms/internal/resources"
)

// Ensure KMSProvider satisfies the provider.Provider interface.
var _ provider.Provider = &KMSProvider{}
var _ provider.ProviderWithFunctions = &KMSProvider{}

// KMSProvider is the root Terraform provider implementation.
type KMSProvider struct {
	version string
}

// KMSProviderModel mirrors the HCL provider block attributes.
type KMSProviderModel struct {
	ServerURL   types.String `tfsdk:"server_url"`
	APIKey      types.String `tfsdk:"api_key"`
	TLSCertFile types.String `tfsdk:"tls_cert_file"`
	TLSKeyFile  types.String `tfsdk:"tls_key_file"`
	CACertFile  types.String `tfsdk:"ca_cert_file"`
}

// New returns a provider factory function used by main.go.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &KMSProvider{version: version}
	}
}

// Metadata returns the provider type name and version.
func (p *KMSProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "kms"
	resp.Version = p.version
}

// Schema declares the provider-level HCL attributes.
func (p *KMSProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The **Cosmian KMS** provider manages cryptographic objects (keys, certificates, access rights) on a [Cosmian KMS](https://github.com/Cosmian/kms) server via KMIP 2.1 over HTTP.",
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the KMS server, e.g. `https://kms.example.com:9998`. May be set via `COSMIAN_KMS_SERVER_URL`.",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "Bearer API key for authentication. May be set via `COSMIAN_KMS_API_KEY`.",
				Optional:            true,
				Sensitive:           true,
			},
			"tls_cert_file": schema.StringAttribute{
				MarkdownDescription: "Path to a PEM client certificate for mTLS authentication.",
				Optional:            true,
			},
			"tls_key_file": schema.StringAttribute{
				MarkdownDescription: "Path to the PEM private key corresponding to `tls_cert_file`.",
				Optional:            true,
			},
			"ca_cert_file": schema.StringAttribute{
				MarkdownDescription: "Path to a PEM CA bundle to verify the KMS server certificate.",
				Optional:            true,
			},
		},
	}
}

// Configure creates the shared KMS client and makes it available to resources
// and data sources via the configure request.
func (p *KMSProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data KMSProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	serverURL := coalesce(data.ServerURL.ValueString(), os.Getenv("COSMIAN_KMS_SERVER_URL"), "http://localhost:9998")
	apiKey := coalesce(data.APIKey.ValueString(), os.Getenv("COSMIAN_KMS_API_KEY"))

	cfg := kmsClient.Config{
		ServerURL:   serverURL,
		APIKey:      apiKey,
		TLSCertFile: data.TLSCertFile.ValueString(),
		TLSKeyFile:  data.TLSKeyFile.ValueString(),
		CACertFile:  data.CACertFile.ValueString(),
	}

	client, err := kmsClient.New(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create KMS client", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

// Resources returns the list of resource types this provider manages.
func (p *KMSProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewSymmetricKeyResource,
		resources.NewKeyPairResource,
		resources.NewCertificateResource,
		resources.NewAccessRightResource,
	}
}

// DataSources returns the list of data source types.
func (p *KMSProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		datasources.NewSymmetricKeyDataSource,
		datasources.NewKeyPairDataSource,
		datasources.NewAccessListDataSource,
	}
}

// Functions returns provider-level functions (none currently).
func (p *KMSProvider) Functions(_ context.Context) []func() function.Function {
	return nil
}

// coalesce returns the first non-empty string from the arguments.
func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
