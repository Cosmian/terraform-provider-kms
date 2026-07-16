// Package datasources implements Terraform data sources for Cosmian KMS.
package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

var _ datasource.DataSource = &SymmetricKeyDataSource{}

// SymmetricKeyDataSource reads an existing symmetric key by UID.
type SymmetricKeyDataSource struct {
	client *kmsClient.Client
}

// SymmetricKeyDataModel is the Terraform state model for the data source.
type SymmetricKeyDataModel struct {
	UniqueIdentifier types.String `tfsdk:"unique_identifier"`
}

// NewSymmetricKeyDataSource is the constructor used in the provider.
func NewSymmetricKeyDataSource() datasource.DataSource {
	return &SymmetricKeyDataSource{}
}

// Metadata returns the data source type name.
func (d *SymmetricKeyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_symmetric_key"
}

// Schema declares the HCL attributes.
func (d *SymmetricKeyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads an existing symmetric key from the Cosmian KMS by UID (calls KMIP `GetAttributes`).",
		Attributes: map[string]schema.Attribute{
			"unique_identifier": schema.StringAttribute{
				MarkdownDescription: "KMS object UID of the symmetric key to look up.",
				Required:            true,
			},
		},
	}
}

// Configure injects the KMS client.
func (d *SymmetricKeyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read calls KMIP GetAttributes to verify the object exists.
func (d *SymmetricKeyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SymmetricKeyDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := d.client.GetAttributes(ctx, data.UniqueIdentifier.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Symmetric key not found", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
