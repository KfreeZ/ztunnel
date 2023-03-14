use boring_sys;
use boring_sys::ssl_private_key_method_st;
use boring_sys::ssl_private_key_result_t;
use boring_sys::SSL;
use libqat_sys;
use tokio::time::{sleep, Duration};
use once_cell::sync::Lazy;
use tracing::{debug, info};
use tokio::task;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::Notify;


pub struct QatPrivateKeyMethodProviderConfig {
    pKey: Vec<u8>,
    poll_delay: tokio::time::Duration,
}

impl QatPrivateKeyMethodProviderConfig {
    pub fn new() -> QatPrivateKeyMethodProviderConfig {
        QatPrivateKeyMethodProviderConfig {
            pKey: vec![1], 
            poll_delay: tokio::time::Duration::from_secs(1),
        }
    }
}
pub struct QatPrivateKeyMethodProvider {
    qat_manager: QatManager,
    qat_section: QatSection,
    private_key_methods: ssl_private_key_method_st,
    private_key: Vec<u8>,
}

impl QatPrivateKeyMethodProvider {
    pub fn new(conf: QatPrivateKeyMethodProviderConfig) -> QatPrivateKeyMethodProvider {
        QatPrivateKeyMethodProvider {
            qat_manager: *QAT_MANAGER_SINGLETON,
            qat_section: QatSection::new(conf.poll_delay),
            private_key_methods: ssl_private_key_method_st {
                sign: Some(Self::my_sign),
                decrypt: Some(Self::my_decrypt),
                complete: Some(Self::my_complete),
                // set other function pointers
            },
            private_key: conf.pKey,
        }
    }


    //TODO this may be moved to somewhere else
    pub fn set_private_key_method(&mut self, ssl : *mut boring_sys::SSL_CTX ) {
        unsafe {
            boring_sys::SSL_CTX_set_private_key_method(ssl, &self.private_key_methods);
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

/**
 * QatManager is a singleton to oversee QAT hardware.
 */
struct QatManager {}
static QAT_MANAGER_SINGLETON: Lazy<QatManager> = Lazy::new(|| QatManager::new());

impl QatManager {
    fn new() -> QatManager {
        let process = std::ffi::CString::new("SSL").unwrap();
        let status = libqat_sys::icp_sal_userStart(process.as_ptr());
        assert_eq!(status, libqat_sys::CPA_STATUS_SUCCESS as i32);
        QatManager{}
    }

    // async fn qat_poll(handle: &QatHandle, poll_delay: tokio::time::Duration) {
    //     libqat_sys::icpSalCyPollInstance(handle.getHandle(), 0);
    // }

    fn connection_index() -> i32 {
        0
    }

    fn context_index() -> i32 {
        0
    }
}

impl Drop for QatManager {
    fn drop(&mut self) {
        libqat_sys::icp_sal_userStop();
    }
}

/**
 * QatSection represents a section definition in QAT configuration. 
 * Its main purpose is to initalize HW and load balance operations to the QAT handles.
 */
struct QatSection {
    qat_handles_: Vec<QatHandle>,
    num_instances_: libqat_sys::Cpa16U,
    next_handle_: i32,
}

impl QatSection {
    fn new(poll_delay: Duration) -> QatSection {
        QatSection {
            qat_handles_: vec![],
            num_instances_: 0,
            next_handle_: 0,
        }
    }

    fn start_section(&mut self, poll_delay: Duration) -> bool {

        let mut num_instances:u16 = 0;
        let status = libqat_sys::cpaCyGetNumInstances(&mut self.num_instances_ as *mut u16);
        assert_eq!(status, libqat_sys::CPA_STATUS_SUCCESS as i32);
        info!("found {} QAT instances", num_instances);

        let mut cpa_instances = Vec::with_capacity(self.num_instances_ as usize);

        let status = libqat_sys::cpaCyGetInstances(self.num_instances_, cpa_instances.as_mut_ptr());
        assert_eq!(status, libqat_sys::CPA_STATUS_SUCCESS as i32);

        self.qat_handles_ = Vec::with_capacity(self.num_instances_ as usize);

        for i in 0..self.num_instances_ {
            if !self.qat_handles_[i as usize].init_qat_instance(cpa_instances[i as usize]) {
                return false;
            }

            // Every handle has a polling thread associated with it. This is needed
            // until qatlib implements event-based notifications when the QAT operation
            // is ready.
            let qat_handle = Arc::new(Mutex::new(self.qat_handles_[i as usize]));
            let cpa_handle= Arc::new(Mutex::new(cpa_instances[i as usize]));
            let thread = std::thread::spawn( move || { //cannot use tokio::spawn here
                Self::poll_task(qat_handle, poll_delay)
            });
            // self.qat_handles_[i as usize].polling_thread_ = Some(thread);
        }
        return true;
    }


    fn poll_task(
        handle: Arc<Mutex<QatHandle>>,
        delay: Duration,
    ) {
            loop {
                {
                    let handle = handle.lock().unwrap();
                    // handle.poll_lock_.lock().unwrap();
                    if handle.is_done() {
                        return;
                    }
                    if !handle.has_users() {
                        // handle.qat_thread_cond_.notified().await;
                    }
                }
                let handle = handle.lock().unwrap();
                // handle.poll_lock_.lock().unwrap();
                libqat_sys::icp_sal_CyPollInstance(handle.get_handle(), 0);    
                sleep(delay);
        }

    }
}



struct QatConnection{
    qat_handle: QatHandle,
    private_key: boring_sys::EVP_PKEY,

}

impl QatConnection {
    pub fn get_qat_handle(&self) -> QatHandle {
        self.qat_handle
    }

    pub fn get_private_key(&self) -> boring_sys::EVP_PKEY {
        self.private_key
    }

    pub fn register_private_key_methods() {
        //register PKM to ssl context via set_ex_data
    }

    pub fn unregister_private_key_methodss() {
        //un-register PKM to ssl context via set_ex_data
    }



}


unsafe impl Send for QatHandle {}
/**
 * Represents a QAT hardware instance.
 */
struct QatHandle {
    cpq_handle_: libqat_sys::CpaInstanceHandle,
    info_: libqat_sys::CpaInstanceInfo2,
    job_is_done: bool,
    polling_thread_: Option<tokio::task::JoinHandle<()>>,
    poll_lock_: Arc<Mutex<u32>>,
    qat_thread_cond_: Arc<Notify>,
    users_: u32,
    //libqat_ 
}

impl QatHandle {
    pub fn is_done(&self) -> bool {
        self.job_is_done
    }

    pub fn init_qat_instance(&self, handle: libqat_sys::CpaInstanceHandle) -> bool {
        self.cpq_handle_ = handle;
        unsafe {
            let status = libqat_sys::cpaCySetAddressTranslation (self.cpq_handle_, Some(libqat_sys::qaeVirtToPhysNUMA));
            if status != libqat_sys::CPA_STATUS_SUCCESS as i32 {
                return false;
            }

            status = libqat_sys::cpaCyInstanceGetInfo2(self.cpq_handle_, &mut self.info_ as *mut _);

            if status != libqat_sys::CPA_STATUS_SUCCESS as i32 {
                return false;
            }

            status = libqat_sys::cpaCyStartInstance(self.cpq_handle_);

            if status != libqat_sys::CPA_STATUS_SUCCESS as i32 {
                return false;
            }

            return true;
        }
    }

    pub fn get_handle(&self) -> libqat_sys::CpaInstanceHandle {
        self.cpq_handle_
    }

    fn has_users (&self) -> bool {
        self.users_ > 0
    }

    fn add_user(&self) {
        self.users_ += 1;
    }

    fn remove_user(&self) {
        assert!(self.users_ > 0);
        self.users_ -= 1;
    }

    fn get_node_affinity(&self) -> u32{
        self.info_.nodeAffinity
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
