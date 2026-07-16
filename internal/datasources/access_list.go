package datasources

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

var _ datasource.DataSource = &AccessListDataSource{}

// AccessListDataSource lists all access rights for a KMS object.
type AccessListDataSource struct {
	client *kmsClient.Client
}

// AccessListDataModel is the Terraform state model.
type AccessListDataModel struct {
	ObjectUID types.String `tfsdk:"object_uid"`
	// Computed: list of {user_id, operations} objects
	Accesses types.List `tfsdk:"accesses"`
}

// AccessEntryModel mirrors the KMS UserAccessResponse JSON.
type AccessEntryModel struct {
	UserID     types.String `tfsdk:"user_id"`
	Operations types.List   `tfsdk:"operations"`
}

var accessEntryAttrTypes = map[string]attr.Type{
	"user_id":    types.StringType,
	"operations": types.ListType{ElemType: types.StringType},
}

// NewAccessListDataSource is the constructor used in the provider.
func NewAccessListDataSource() datasource.DataSource {
	return &AccessListDataSource{}
}

// Metadata returns the data source type name.
func (d *AccessListDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_list"
}

// Schema declares the HCL attributes.
func (d *AccessListDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists all access rights for a KMS object (calls `GET /access/list/{object_uid}`).",
		Attributes: map[string]schema.Attribute{
			"object_uid": schema.StringAttribute{
				MarkdownDescription: "KMS object UID to list access rights for.",
				Required:            true,
			},
			"accesses": schema.ListNestedAttribute{
				MarkdownDescription: "Access entries, one per user.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"user_id": schema.StringAttribute{
							MarkdownDescription: "User identifier.",
							Computed:            true,
						},
						"operations": schema.ListAttribute{
							MarkdownDescription: "Granted KMIP operations.",
							Computed:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
		},
	}
}

// Configure injects the KMS client.
func (d *AccessListDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read calls GET /access/list/{object_uid} and populates state.
func (d *AccessListDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AccessListDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// GET /access/list/{object_uid} returns []UserAccessResponse
	raw, err := d.client.ListAccesses(ctx, data.ObjectUID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to list accesses", err.Error())
		return
	}

	// Convert []map[string]any → types.List of AccessEntryModel
	var entries []attr.Value
	for _, entry := range raw {
		userID, _ := entry["user_id"].(string)

		var opsVals []attr.Value
		if ops, ok := entry["operations"].([]any); ok {
			for _, op := range ops {
				if s, ok := op.(string); ok {
					opsVals = append(opsVals, types.StringValue(s))
				}
			}
		}
		opsList, diags := types.ListValue(types.StringType, opsVals)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		obj, diags := types.ObjectValue(accessEntryAttrTypes, map[string]attr.Value{
			"user_id":    types.StringValue(userID),
			"operations": opsList,
		})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		entries = append(entries, obj)
	}

	accessList, diags := types.ListValue(types.ObjectType{AttrTypes: accessEntryAttrTypes}, entries)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Accesses = accessList
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// ListAccesses calls GET /access/list/{uid} and returns the raw JSON array.
// This method is defined on the Client in the client package; declared here via
// an interface extension to avoid a circular import.
func init() {
	// Compile-time check: kmsClient.Client must expose ListAccesses.
	var _ interface {
		ListAccesses(ctx context.Context, uid string) ([]map[string]any, error)
	} = (*kmsClient.Client)(nil)
}

// Keep the unused import satisfied.
var _ = http.MethodGet
