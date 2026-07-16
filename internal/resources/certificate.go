package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
)

var _ resource.Resource = &CertificateResource{}
var _ resource.ResourceWithImportState = &CertificateResource{}

// CertificateResource manages cosmian_kms_certificate resources.
type CertificateResource struct {
	client *kmsClient.Client
}

// CertificateModel is the Terraform state model.
type CertificateModel struct {
	ID                  types.String `tfsdk:"id"`
	SubjectCN           types.String `tfsdk:"subject_cn"`
	SubjectO            types.String `tfsdk:"subject_o"`
	SubjectC            types.String `tfsdk:"subject_c"`
	PublicKeyUID        types.String `tfsdk:"public_key_uid"`
	PrivateKeyUID       types.String `tfsdk:"private_key_uid"`
	IssuerPrivateKeyUID types.String `tfsdk:"issuer_private_key_uid"`
	ValidityDays        types.Int64  `tfsdk:"validity_days"`
	IsCA                types.Bool   `tfsdk:"is_ca"`
}

// NewCertificateResource is the constructor used in the provider.
func NewCertificateResource() resource.Resource {
	return &CertificateResource{}
}

// Metadata returns the resource type name.
func (r *CertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

// Schema declares the HCL attributes.
func (r *CertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates an X.509 certificate in the Cosmian KMS via KMIP `Certify`. The key pair must already exist. The private key is activated automatically before certification.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "KMS object UID of the created certificate.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"subject_cn": schema.StringAttribute{
				MarkdownDescription: "Certificate subject Common Name (CN).",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"subject_o": schema.StringAttribute{
				MarkdownDescription: "Certificate subject Organisation (O).",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"subject_c": schema.StringAttribute{
				MarkdownDescription: "Certificate subject Country (C), 2-letter ISO code.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"public_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the public key to certify.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"private_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the private key (activated before Certify, used as signing key for self-signed).",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"issuer_private_key_uid": schema.StringAttribute{
				MarkdownDescription: "KMS UID of the CA private key to sign with. If omitted, the certificate is self-signed.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"validity_days": schema.Int64Attribute{
				MarkdownDescription: "Certificate validity in days (default: 365).",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"is_ca": schema.BoolAttribute{
				MarkdownDescription: "Whether the certificate is a CA certificate.",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
		},
	}
}

// Configure injects the KMS client.
func (r *CertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create activates the private key, then calls KMIP Certify.
func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Activate the private key so it can be used for signing.
	if err := r.client.Activate(ctx, data.PrivateKeyUID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to activate private key before Certify", err.Error())
		return
	}

	issuer := data.IssuerPrivateKeyUID.ValueString()

	certUID, err := r.client.Certify(ctx, kmsClient.CertificateParams{
		PublicKeyUID:        data.PublicKeyUID.ValueString(),
		SubjectCN:           data.SubjectCN.ValueString(),
		SubjectO:            data.SubjectO.ValueString(),
		SubjectC:            data.SubjectC.ValueString(),
		IssuerPrivateKeyUID: issuer,
		ValidityDays:        int(data.ValidityDays.ValueInt64()),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to certify key", err.Error())
		return
	}

	data.ID = types.StringValue(certUID)
	if data.ValidityDays.IsNull() || data.ValidityDays.IsUnknown() {
		data.ValidityDays = types.Int64Value(365)
	}
	if data.IsCA.IsNull() || data.IsCA.IsUnknown() {
		data.IsCA = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read calls GetAttributes to verify the certificate still exists.
func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exists, err := r.client.ObjectExists(ctx, data.ID.ValueString())
	if err != nil || !exists {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is not supported.
func (r *CertificateResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "cosmian_kms_certificate does not support in-place update.")
}

// Delete calls KMIP Destroy on the certificate.
func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.Destroy(ctx, data.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to destroy certificate", err.Error())
	}
}

// ImportState imports an existing certificate by UID.
func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	state := CertificateModel{ID: types.StringValue(req.ID)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
