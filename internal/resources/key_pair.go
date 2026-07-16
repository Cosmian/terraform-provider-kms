package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

var _ resource.Resource = &KeyPairResource{}
var _ resource.ResourceWithImportState = &KeyPairResource{}

// KeyPairResource manages cosmian_kms_key_pair resources.
type KeyPairResource struct {
	client *kmsClient.Client
}

// KeyPairModel is the Terraform state model for a key pair.
type KeyPairModel struct {
	// Computed: set after creation.
	ID            types.String `tfsdk:"id"` // private_uid:public_uid composite
	PrivateKeyUID types.String `tfsdk:"private_key_uid"`
	PublicKeyUID  types.String `tfsdk:"public_key_uid"`
	// Input attributes.
	Algorithm     types.String `tfsdk:"algorithm"`
	KeyLengthBits types.Int64  `tfsdk:"key_length_bits"`
	Name          types.String `tfsdk:"name"`
}

// NewKeyPairResource is the constructor used in the provider.
func NewKeyPairResource() resource.Resource {
	return &KeyPairResource{}
}

// Metadata returns the resource type name.
func (r *KeyPairResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_pair"
}

// Schema declares the HCL attributes.
func (r *KeyPairResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates an asymmetric key pair in the Cosmian KMS via KMIP `CreateKeyPair`.\n\nImport syntax: `terraform import cosmian_kms_key_pair.name private_uid:public_uid`",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Composite identifier `private_uid:public_uid`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"private_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the private key.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"public_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the public key.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"algorithm": schema.StringAttribute{
				MarkdownDescription: "Algorithm: `RSA`, `EC`, `Ed25519`, `X25519`.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"key_length_bits": schema.Int64Attribute{
				MarkdownDescription: "Key size in bits (RSA: 2048/3072/4096; EC: 224/256/384/521).",
				Required:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-readable name for the key pair.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
	}
}

// Configure injects the KMS client.
func (r *KeyPairResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create calls KMIP CreateKeyPair.
func (r *KeyPairResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyPairModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	privUID, pubUID, err := r.client.CreateKeyPair(ctx, kmsClient.KeyPairParams{
		Algorithm:     data.Algorithm.ValueString(),
		KeyLengthBits: int(data.KeyLengthBits.ValueInt64()),
		Name:          data.Name.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create key pair", err.Error())
		return
	}

	data.PrivateKeyUID = types.StringValue(privUID)
	data.PublicKeyUID = types.StringValue(pubUID)
	data.ID = types.StringValue(privUID + ":" + pubUID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read calls GetAttributes on both keys to confirm existence.
func (r *KeyPairResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeyPairModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	privExists, _ := r.client.ObjectExists(ctx, data.PrivateKeyUID.ValueString())
	pubExists, _ := r.client.ObjectExists(ctx, data.PublicKeyUID.ValueString())

	if !privExists || !pubExists {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is not supported — all attributes force replacement.
func (r *KeyPairResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "cosmian_kms_key_pair does not support in-place update.")
}

// Delete destroys both the private and public key.
func (r *KeyPairResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KeyPairModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.Destroy(ctx, data.PrivateKeyUID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to destroy private key", err.Error())
	}
	if err := r.client.Destroy(ctx, data.PublicKeyUID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to destroy public key", err.Error())
	}
}

// ImportState handles `terraform import cosmian_kms_key_pair.name private_uid:public_uid`.
func (r *KeyPairResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Parse "private_uid:public_uid"
	var privUID, pubUID string
	if _, err := fmt.Sscanf(req.ID, "%s", &privUID); err != nil || req.ID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "expected format: private_uid:public_uid")
		return
	}
	for i, c := range req.ID {
		if c == ':' && i > 0 {
			privUID = req.ID[:i]
			pubUID = req.ID[i+1:]
			break
		}
	}
	if pubUID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "expected format: private_uid:public_uid")
		return
	}

	state := KeyPairModel{
		ID:            types.StringValue(req.ID),
		PrivateKeyUID: types.StringValue(privUID),
		PublicKeyUID:  types.StringValue(pubUID),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
