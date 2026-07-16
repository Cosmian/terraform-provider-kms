package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

var _ datasource.DataSource = &KeyPairDataSource{}

// KeyPairDataSource looks up an existing key pair by private + public UIDs.
type KeyPairDataSource struct {
	client *kmsClient.Client
}

// KeyPairDataModel is the Terraform state model.
type KeyPairDataModel struct {
	PrivateKeyUID types.String `tfsdk:"private_key_uid"`
	PublicKeyUID  types.String `tfsdk:"public_key_uid"`
}

// NewKeyPairDataSource is the constructor used in the provider.
func NewKeyPairDataSource() datasource.DataSource {
	return &KeyPairDataSource{}
}

// Metadata returns the data source type name.
func (d *KeyPairDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_pair"
}

// Schema declares the HCL attributes.
func (d *KeyPairDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads an existing key pair from the Cosmian KMS by UID. Calls KMIP `GetAttributes` on both keys.",
		Attributes: map[string]schema.Attribute{
			"private_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the private key.",
				Required:            true,
			},
			"public_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the public key.",
				Required:            true,
			},
		},
	}
}

// Configure injects the KMS client.
func (d *KeyPairDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*kmsClient.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.client = client
}

// Read calls GetAttributes on both keys to verify they exist.
func (d *KeyPairDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data KeyPairDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := d.client.GetAttributes(ctx, data.PrivateKeyUID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Private key not found", err.Error())
	}
	if _, err := d.client.GetAttributes(ctx, data.PublicKeyUID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Public key not found", err.Error())
	}
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
