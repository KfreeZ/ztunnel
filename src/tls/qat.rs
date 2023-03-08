use boring_sys;
use boring_sys::ssl_private_key_method_st;
use boring_sys::ssl_private_key_result_t;
use boring_sys::SSL;
use libqat_sys;


pub struct QatPrivateKeyProvider {}

impl QatPrivateKeyProvider {
    //TODO this may be moved to somewhere else
    pub fn set_private_key_method(ssl : *mut boring_sys::SSL_CTX ) {
        let key_method = ssl_private_key_method_st {
            sign: Some(Self::my_sign),
            decrypt: Some(Self::my_decrypt),
            complete: Some(Self::my_complete),
            // set other function pointers
        };

        unsafe {
            boring_sys::SSL_CTX_set_private_key_method(ssl, &key_method);
        }
    }

    pub fn qat_connection() {}

    // define your own function pointers
    unsafe extern "C" fn my_sign(
        _ctx: *mut SSL,
        _out: *mut u8,
        _out_len: *mut usize,
        _max_out: usize,
        _algo: u16,
        _in_: *const u8,
        _in_len: usize,
    ) -> ssl_private_key_result_t {
        // implement your own signing function
        return ssl_private_key_result_t(2);
    }

    unsafe extern "C" fn my_decrypt(
        _ctx: *mut SSL,
        _out: *mut u8,
        _out_len: *mut usize,
        _max_out: usize,
        _in_: *const u8,
        _in_len: usize,
    ) -> ssl_private_key_result_t {
        // implement your own decryption function
        return ssl_private_key_result_t(2);
    }

    unsafe extern "C" fn my_complete(
        _ctx: *mut SSL,
        _out: *mut u8,
        _out_len: *mut usize,
        _max_out: usize,
    ) -> ssl_private_key_result_t {
        // implement your own finish function
        return ssl_private_key_result_t(2);
    }
}

struct QatManager {}

impl QatManager {
    fn qat_poll() {}

    fn connection_index() -> i32 {
        0
    }

    fn context_index() -> i32 {
        0
    }
}

struct LibQatCrypto {}

impl LibQatCrypto {
    /* defined in contrib/qat/private_key_providers/source/libqat.h

    pub fn icp_sal_userStart(pProcessName: *const ::std::os::raw::c_char) -> CpaStatus;

    pub fn cpaGetNumInstances(
        accelerationServiceType: CpaAccelerationServiceType,
        pNumInstances: *mut Cpa16U,
    ) -> CpaStatus;

    pub fn cpaGetInstances(
        accelerationServiceType: CpaAccelerationServiceType,
        numInstances: Cpa16U,
        cpaInstances: *mut CpaInstanceHandle,
    ) -> CpaStatus;

    pub fn cpaCySetAddressTranslation(
        instanceHandle: CpaInstanceHandle,
        virtual2Physical: CpaVirtualToPhysical,
    ) -> CpaStatus;

    pub fn cpaCyInstanceGetInfo2(
        instanceHandle: CpaInstanceHandle,
        pInstanceInfo2: *mut CpaInstanceInfo2,
    ) -> CpaStatus;

    cpaCyStartInstance(instanceHandle: CpaInstanceHandle) -> CpaStatus;

    pub fn qaeMemAllocNUMA(
        size: usize,
        node: ::std::os::raw::c_int,
        phys_alignment_byte: usize,
    ) -> *mut ::std::os::raw::c_void;

    qaeMemFreeNUMA(ptr: *mut *mut ::std::os::raw::c_void);

    pub fn cpaCyRsaDecrypt(
        instanceHandle: CpaInstanceHandle,
        pRsaDecryptCb: CpaCyGenFlatBufCbFunc,
        pCallbackTag: *mut ::std::os::raw::c_void,
        pDecryptOpData: *const CpaCyRsaDecryptOpData,
        pOutputData: *mut CpaFlatBuffer,
    ) -> CpaStatus;

    pub fn icp_sal_userStop() -> CpaStatus;

    pub fn icp_sal_CyPollInstance(
        instanceHandle: CpaInstanceHandle,
        response_quota: Cpa32U,
    ) -> CpaStatus;

    pub fn cpaCyStopInstance(instanceHandle: CpaInstanceHandle) -> CpaStatus;

    also found in libqat_sys */
}
