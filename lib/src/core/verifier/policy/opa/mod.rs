use anyhow::{anyhow, Result};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Link import cgo function
#[link(name = "opa")]
extern "C" {
    pub fn evaluateGo(policy: GoString, data: GoString, input: GoString) -> *mut c_char;
}

/// String structure passed into cgo
#[derive(Debug)]
#[repr(C)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

pub fn evaluate(policy: String, reference: String, input: String) -> Result<String> {
    let policy_go = GoString {
        p: policy.as_ptr() as *const i8,
        n: policy.len() as isize,
    };

    let reference_go = GoString {
        p: reference.as_ptr() as *const i8,
        n: reference.len() as isize,
    };

    let input_go = GoString {
        p: input.as_ptr() as *const i8,
        n: input.len() as isize,
    };

    // Call the function exported by cgo and process the returned decision
    let decision_buf: *mut c_char = unsafe { evaluateGo(policy_go, reference_go, input_go) };
    let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
    let res = decision_str.to_str()?.to_string();
    debug!("Evaluated:\n{}", res);
    match res.starts_with("Error::") {
        true => Err(anyhow!(res)),
        false => Ok(res),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Result, Value};

    fn dummy_policy() -> Result<String> {
        let policy = r#"
package policy
        
# By default, deny requests.
default allow = false

allow {
    input.productId >= data.productId
    input.svn >= data.svn
}
"#;

        Ok(policy.to_string())
    }

    fn dummy_reference() -> Result<String> {
        let reference = r#"{
    "productId": 1,
    "svn": 1
}"#;

        Ok(reference.to_string())
    }

    fn dummy_input() -> Result<String> {
        let input = r#"{
    "productId": 1,
    "svn": 1
}"#;
        Ok(input.to_string())
    }

    fn dummy_input2() -> Result<String> {
        let input = r#"{
    "productId": 0,
    "svn": 0
}"#;
        Ok(input.to_string())
    }

    #[test]
    fn test_evaluate() {
        let policy = dummy_policy().unwrap();
        let reference = dummy_reference().unwrap();

        let input = dummy_input().unwrap();
        let res = evaluate(policy.clone(), reference.clone(), input);
        assert!(res.is_ok(), "OPA execution() should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert!(v["allow"] == true, "should allowed");

        let input = dummy_input2().unwrap();
        let res = evaluate(policy.clone(), reference.clone(), input);
        assert!(res.is_ok(), "OPA execution() should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert!(v["allow"] == false, "should not allowed");
    }
}
