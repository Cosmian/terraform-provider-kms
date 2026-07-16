package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

var _ resource.Resource = &AccessRightResource{}
var _ resource.ResourceWithImportState = &AccessRightResource{}

// AccessRightResource manages cosmian_kms_access_right resources.
type AccessRightResource struct {
	client *kmsClient.Client
}

// AccessRightModel is the Terraform state model.
type AccessRightModel struct {
	// Computed composite ID: object_uid/user_id
	ID         types.String `tfsdk:"id"`
	ObjectUID  types.String `tfsdk:"object_uid"`
	UserID     types.String `tfsdk:"user_id"`
	Operations types.List   `tfsdk:"operations"`
}

// NewAccessRightResource is the constructor used in the provider.
func NewAccessRightResource() resource.Resource {
	return &AccessRightResource{}
}

// Metadata returns the resource type name.
func (r *AccessRightResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_right"
}

// Schema declares the HCL attributes.
func (r *AccessRightResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Grants a set of KMIP operations on a KMS object to a user via `POST /access/grant`. On destroy, revokes the same operations via `POST /access/revoke`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Composite identifier `object_uid/user_id`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"object_uid": schema.StringAttribute{
				MarkdownDescription: "UID of the KMS object to grant access to.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"user_id": schema.StringAttribute{
				MarkdownDescription: "Identity of the user receiving access (e.g. `alice@example.com`).",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"operations": schema.ListAttribute{
				MarkdownDescription: "KMIP operations to grant: `Get`, `Decrypt`, `Encrypt`, `Sign`, `Verify`, `Destroy`, etc.",
				Required:            true,
				ElementType:         types.StringType,
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
		},
	}
}

// Configure injects the KMS client.
func (r *AccessRightResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*kmsClient.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.client = client
}

// Create calls POST /access/grant.
func (r *AccessRightResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AccessRightModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ops []string
	resp.Diagnostics.Append(data.Operations.ElementsAs(ctx, &ops, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.GrantAccess(ctx, kmsClient.AccessRightParams{
		ObjectUID:      data.ObjectUID.ValueString(),
		UserID:         data.UserID.ValueString(),
		OperationTypes: ops,
	}); err != nil {
		resp.Diagnostics.AddError("Failed to grant access", err.Error())
		return
	}

	data.ID = types.StringValue(data.ObjectUID.ValueString() + "/" + data.UserID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is a no-op — the KMS /access/list endpoint could be used here in a future iteration.
func (r *AccessRightResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AccessRightModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is not supported.
func (r *AccessRightResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "cosmian_kms_access_right does not support in-place update; change any attribute to trigger recreation.")
}

// Delete calls POST /access/revoke.
func (r *AccessRightResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AccessRightModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ops []string
	resp.Diagnostics.Append(data.Operations.ElementsAs(ctx, &ops, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.RevokeAccess(ctx, kmsClient.AccessRightParams{
		ObjectUID:      data.ObjectUID.ValueString(),
		UserID:         data.UserID.ValueString(),
		OperationTypes: ops,
	}); err != nil {
		resp.Diagnostics.AddError("Failed to revoke access", err.Error())
	}
}

// ImportState parses "object_uid/user_id".
func (r *AccessRightResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("Invalid import ID", "expected format: object_uid/user_id")
		return
	}
	state := AccessRightModel{
		ID:        types.StringValue(req.ID),
		ObjectUID: types.StringValue(parts[0]),
		UserID:    types.StringValue(parts[1]),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
