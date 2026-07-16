// Package resources implements Terraform resource types for Cosmian KMS objects.
package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

// Ensure SymmetricKeyResource satisfies the resource.Resource interface.
var _ resource.Resource = &SymmetricKeyResource{}
var _ resource.ResourceWithImportState = &SymmetricKeyResource{}

// SymmetricKeyResource manages cosmian_kms_symmetric_key resources.
type SymmetricKeyResource struct {
	client *kmsClient.Client
}

// SymmetricKeyModel is the Terraform state model.
type SymmetricKeyModel struct {
	ID            types.String `tfsdk:"id"`
	Algorithm     types.String `tfsdk:"algorithm"`
	KeyLengthBits types.Int64  `tfsdk:"key_length_bits"`
	Name          types.String `tfsdk:"name"`
	Tags          types.List   `tfsdk:"tags"`
}

// NewSymmetricKeyResource is the constructor used in the provider.
func NewSymmetricKeyResource() resource.Resource {
	return &SymmetricKeyResource{}
}

// Metadata returns the resource type name.
func (r *SymmetricKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_symmetric_key"
}

// Schema declares the HCL attributes for this resource.
func (r *SymmetricKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates a symmetric cryptographic key in the Cosmian KMS via KMIP `Create`. The resource ID is the KMS object UID.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "KMS object UID assigned on creation.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"algorithm": schema.StringAttribute{
				MarkdownDescription: "Cryptographic algorithm, e.g. `AES`, `ChaCha20`.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"key_length_bits": schema.Int64Attribute{
				MarkdownDescription: "Key length in bits, e.g. `128`, `192`, `256`.",
				Required:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-readable object name stored as a KMIP Name attribute.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"tags": schema.ListAttribute{
				MarkdownDescription: "Arbitrary string tags attached to the object.",
				Optional:            true,
				ElementType:         types.StringType,
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
		},
	}
}

// Configure injects the KMS client.
func (r *SymmetricKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create calls KMIP Create and stores the new UID in state.
func (r *SymmetricKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SymmetricKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var tags []string
	resp.Diagnostics.Append(data.Tags.ElementsAs(ctx, &tags, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	uid, err := r.client.CreateSymmetricKey(ctx, kmsClient.SymmetricKeyParams{
		Algorithm:     data.Algorithm.ValueString(),
		KeyLengthBits: int(data.KeyLengthBits.ValueInt64()),
		Name:          data.Name.ValueString(),
		Tags:          tags,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create symmetric key", err.Error())
		return
	}

	data.ID = types.StringValue(uid)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read calls KMIP GetAttributes to verify the object still exists.
func (r *SymmetricKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SymmetricKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exists, err := r.client.ObjectExists(ctx, data.ID.ValueString())
	if err != nil || !exists {
		// Object no longer exists or is Destroyed — remove from state.
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is not supported — all attributes force replacement.
func (r *SymmetricKeyResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "cosmian_kms_symmetric_key does not support in-place update; change any attribute to trigger recreation.")
}

// Delete calls KMIP Destroy.
func (r *SymmetricKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SymmetricKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.Destroy(ctx, data.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to destroy symmetric key", err.Error())
	}
}

// ImportState imports an existing KMS object by UID.
func (r *SymmetricKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Populate only the ID; Read will reconcile remaining attributes.
	state := SymmetricKeyModel{ID: types.StringValue(req.ID)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
