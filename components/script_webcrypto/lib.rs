/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![cfg_attr(crown, feature(register_tool))]
// Register the linter `crown`, which is the Servo-specific linter for the script crate.
#![cfg_attr(crown, register_tool(crown))]

pub mod cryptokey;
pub mod subtlecrypto;
pub mod traits;

pub(crate) use js::gc::Traceable as JSTraceable;
pub(crate) use script_bindings::reflector::{DomObject, MutDomObject, Reflector};
pub(crate) use script_bindings::inheritance::HasParent;

// Reexports
pub(crate) mod dom {
    pub(crate) mod types {}
    pub(crate) mod bindings {
        pub(crate) use script_bindings::*;
    }
}

/// Generated JS-Rust bindings.
#[expect(non_snake_case)]
pub(crate) mod codegen {
    #[expect(unused)]
    pub(crate) mod Bindings {
        use std::ptr;

        // use js::context::JSContext;
        // use js::gc::HandleObject;
        pub(crate) use script_bindings::DomTypes;
        use script_bindings::codegen::PrototypeList;
        use script_bindings::conversions::IDLInterface;
        // use script_bindings::reflector::DomObjectWrap;
        pub(crate) use script_bindings::reflector::Reflector;
        // use script_bindings::root::{Dom, DomRoot, Root};
        use script_bindings::utils::DOMClass;
        // use script_bindings::weakref::WeakReferenceable;
        //
        // use crate::gpu::GPU;
        // use crate::gpuadapter::GPUAdapter;
        // use crate::gpuadapterinfo::GPUAdapterInfo;
        // use crate::gpubindgroup::GPUBindGroup;
        // use crate::gpubindgrouplayout::GPUBindGroupLayout;
        // use crate::gpubuffer::GPUBuffer;
        // use crate::gpubufferusage::GPUBufferUsage;
        // use crate::gpucolorwrite::GPUColorWrite;
        // use crate::gpucommandbuffer::GPUCommandBuffer;
        // use crate::gpucommandencoder::GPUCommandEncoder;
        // use crate::gpucompilationinfo::GPUCompilationInfo;
        // use crate::gpucompilationmessage::GPUCompilationMessage;
        // use crate::gpucomputepassencoder::GPUComputePassEncoder;
        // use crate::gpucomputepipeline::GPUComputePipeline;
        // use crate::gpudevice::GPUDevice;
        // use crate::gpudevicelostinfo::GPUDeviceLostInfo;
        // use crate::gpuerror::GPUError;
        // use crate::gpuexternaltexture::GPUExternalTexture;
        // use crate::gpuinternalerror::GPUInternalError;
        // use crate::gpumapmode::GPUMapMode;
        // use crate::gpuoutofmemoryerror::GPUOutOfMemoryError;
        // use crate::gpupipelineerror::GPUPipelineError;
        // use crate::gpupipelinelayout::GPUPipelineLayout;
        // use crate::gpuqueryset::GPUQuerySet;
        // use crate::gpuqueue::GPUQueue;
        // use crate::gpurenderbundle::GPURenderBundle;
        // use crate::gpurenderbundleencoder::GPURenderBundleEncoder;
        // use crate::gpurenderpassencoder::GPURenderPassEncoder;
        // use crate::gpurenderpipeline::GPURenderPipeline;
        // use crate::gpusampler::GPUSampler;
        // use crate::gpushadermodule::GPUShaderModule;
        // use crate::gpushaderstage::GPUShaderStage;
        // use crate::gpusupportedfeatures::GPUSupportedFeatures;
        // use crate::gpusupportedlimits::GPUSupportedLimits;
        // use crate::gputexture::GPUTexture;
        // use crate::gputextureusage::GPUTextureUsage;
        // use crate::gputextureview::GPUTextureView;
        // use crate::gpuuncapturederrorevent::GPUUncapturedErrorEvent;
        // use crate::gpuvalidationerror::GPUValidationError;
        use crate::traits::Equivalence;
        // use crate::wgsllanguagefeatures::WGSLLanguageFeatures;
        // include!(concat!(
        //     env!("OUT_DIR"),
        //     "/ConcreteBindings/WebCryptoBinding.rs"
        // ));
        // include!(concat!(env!("OUT_DIR"), "/ConcreteInheritTypes.rs"));
        use crate::cryptokey::CryptoKey;
        include!(concat!(
            env!("OUT_DIR"),
            "/ConcreteBindings/CryptoKeyBinding.rs"
        ));
    }
}
