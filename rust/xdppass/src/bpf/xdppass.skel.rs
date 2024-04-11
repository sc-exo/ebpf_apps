// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::transmute_ptr_to_ref)]
#![allow(clippy::upper_case_acronyms)]

use libbpf_rs::libbpf_sys;

fn build_skel_config() -> libbpf_rs::Result<libbpf_rs::skeleton::ObjectSkeletonConfig<'static>> {
    let mut builder = libbpf_rs::skeleton::ObjectSkeletonConfigBuilder::new(DATA);
    builder
        .name("xdppass_bpf")
        .map("xdppass_.rodata", true)
        .prog("xdp_prog_simple");

    builder.build()
}

#[derive(Default)]
pub struct XdppassSkelBuilder {
    pub obj_builder: libbpf_rs::ObjectBuilder,
}

impl<'a> XdppassSkelBuilder {
    pub fn open(mut self) -> libbpf_rs::Result<OpenXdppassSkel<'a>> {
        let mut skel_config = build_skel_config()?;
        let open_opts = self.obj_builder.opts(std::ptr::null());

        let ret = unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

        Ok(OpenXdppassSkel { obj, skel_config })
    }

    pub fn open_opts(
        self,
        open_opts: libbpf_sys::bpf_object_open_opts,
    ) -> libbpf_rs::Result<OpenXdppassSkel<'a>> {
        let mut skel_config = build_skel_config()?;

        let ret = unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

        Ok(OpenXdppassSkel { obj, skel_config })
    }
}

pub struct OpenXdppassMaps<'a> {
    inner: &'a libbpf_rs::OpenObject,
}

impl<'a> OpenXdppassMaps<'a> {
    pub fn rodata(&self) -> &libbpf_rs::OpenMap {
        self.inner.map("xdppass_.rodata").unwrap()
    }
}

pub struct OpenXdppassMapsMut<'a> {
    inner: &'a mut libbpf_rs::OpenObject,
}

impl<'a> OpenXdppassMapsMut<'a> {
    pub fn rodata(&mut self) -> &mut libbpf_rs::OpenMap {
        self.inner.map_mut("xdppass_.rodata").unwrap()
    }
}

pub struct OpenXdppassProgs<'a> {
    inner: &'a libbpf_rs::OpenObject,
}

impl<'a> OpenXdppassProgs<'a> {
    pub fn xdp_prog_simple(&self) -> &libbpf_rs::OpenProgram {
        self.inner.prog("xdp_prog_simple").unwrap()
    }
}

pub struct OpenXdppassProgsMut<'a> {
    inner: &'a mut libbpf_rs::OpenObject,
}

impl<'a> OpenXdppassProgsMut<'a> {
    pub fn xdp_prog_simple(&mut self) -> &mut libbpf_rs::OpenProgram {
        self.inner.prog_mut("xdp_prog_simple").unwrap()
    }
}

pub mod xdppass_rodata_types {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct rodata {}
}

pub struct OpenXdppassSkel<'a> {
    pub obj: libbpf_rs::OpenObject,
    skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
}

impl<'a> OpenXdppassSkel<'a> {
    pub fn load(mut self) -> libbpf_rs::Result<XdppassSkel<'a>> {
        let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

        Ok(XdppassSkel {
            obj,
            skel_config: self.skel_config,
            links: XdppassLinks::default(),
        })
    }

    pub fn progs(&self) -> OpenXdppassProgs {
        OpenXdppassProgs { inner: &self.obj }
    }

    pub fn progs_mut(&mut self) -> OpenXdppassProgsMut {
        OpenXdppassProgsMut {
            inner: &mut self.obj,
        }
    }

    pub fn maps(&self) -> OpenXdppassMaps {
        OpenXdppassMaps { inner: &self.obj }
    }

    pub fn maps_mut(&mut self) -> OpenXdppassMapsMut {
        OpenXdppassMapsMut {
            inner: &mut self.obj,
        }
    }

    pub fn rodata(&mut self) -> &'a mut xdppass_rodata_types::rodata {
        unsafe {
            std::mem::transmute::<*mut std::ffi::c_void, &'a mut xdppass_rodata_types::rodata>(
                self.skel_config.map_mmap_ptr(0).unwrap(),
            )
        }
    }
}

pub struct XdppassMaps<'a> {
    inner: &'a libbpf_rs::Object,
}

impl<'a> XdppassMaps<'a> {
    pub fn rodata(&self) -> &libbpf_rs::Map {
        self.inner.map("xdppass_.rodata").unwrap()
    }
}

pub struct XdppassMapsMut<'a> {
    inner: &'a mut libbpf_rs::Object,
}

impl<'a> XdppassMapsMut<'a> {
    pub fn rodata(&mut self) -> &mut libbpf_rs::Map {
        self.inner.map_mut("xdppass_.rodata").unwrap()
    }
}

pub struct XdppassProgs<'a> {
    inner: &'a libbpf_rs::Object,
}

impl<'a> XdppassProgs<'a> {
    pub fn xdp_prog_simple(&self) -> &libbpf_rs::Program {
        self.inner.prog("xdp_prog_simple").unwrap()
    }
}

pub struct XdppassProgsMut<'a> {
    inner: &'a mut libbpf_rs::Object,
}

impl<'a> XdppassProgsMut<'a> {
    pub fn xdp_prog_simple(&mut self) -> &mut libbpf_rs::Program {
        self.inner.prog_mut("xdp_prog_simple").unwrap()
    }
}

#[derive(Default)]
pub struct XdppassLinks {
    pub xdp_prog_simple: Option<libbpf_rs::Link>,
}

pub struct XdppassSkel<'a> {
    pub obj: libbpf_rs::Object,
    skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
    pub links: XdppassLinks,
}

unsafe impl<'a> Send for XdppassSkel<'a> {}

impl<'a> XdppassSkel<'a> {
    pub fn progs(&self) -> XdppassProgs {
        XdppassProgs { inner: &self.obj }
    }

    pub fn progs_mut(&mut self) -> XdppassProgsMut {
        XdppassProgsMut {
            inner: &mut self.obj,
        }
    }

    pub fn maps(&self) -> XdppassMaps {
        XdppassMaps { inner: &self.obj }
    }

    pub fn maps_mut(&mut self) -> XdppassMapsMut {
        XdppassMapsMut {
            inner: &mut self.obj,
        }
    }

    pub fn rodata(&mut self) -> &'a xdppass_rodata_types::rodata {
        unsafe {
            std::mem::transmute::<*mut std::ffi::c_void, &'a xdppass_rodata_types::rodata>(
                self.skel_config.map_mmap_ptr(0).unwrap(),
            )
        }
    }

    pub fn attach(&mut self) -> libbpf_rs::Result<()> {
        let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        self.links = XdppassLinks {
            xdp_prog_simple: (|| {
                let ptr = self.skel_config.prog_link_ptr(0)?;
                if ptr.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(unsafe { libbpf_rs::Link::from_ptr(ptr) }))
                }
            })()?,
        };

        Ok(())
    }
}

const DATA: &[u8] = &[
    127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 64,
    0, 27, 0, 1, 0, 97, 18, 0, 0, 0, 0, 0, 0, 97, 19, 4, 0, 0, 0, 0, 0, 31, 35, 0, 0, 0, 0, 0, 0,
    24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 16, 0, 0, 0, 133, 0, 0, 0, 6, 0,
    0, 0, 183, 0, 0, 0, 2, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 112, 97, 99, 107, 101, 116, 32, 115,
    105, 122, 101, 58, 32, 37, 100, 0, 71, 80, 76, 0, 72, 0, 0, 0, 5, 0, 8, 0, 4, 0, 0, 0, 16, 0,
    0, 0, 22, 0, 0, 0, 40, 0, 0, 0, 58, 0, 0, 0, 4, 0, 40, 1, 81, 0, 4, 8, 48, 13, 114, 0, 168,
    167, 128, 128, 0, 168, 171, 128, 128, 0, 159, 0, 4, 16, 24, 13, 115, 0, 168, 167, 128, 128, 0,
    168, 171, 128, 128, 0, 159, 0, 4, 24, 56, 1, 83, 0, 1, 17, 1, 37, 37, 19, 5, 3, 37, 114, 23,
    16, 23, 27, 37, 17, 27, 18, 6, 115, 23, 140, 1, 23, 0, 0, 2, 36, 0, 3, 37, 62, 11, 11, 11, 0,
    0, 3, 46, 1, 17, 27, 18, 6, 64, 24, 122, 25, 3, 37, 58, 11, 59, 11, 39, 25, 73, 19, 63, 25, 0,
    0, 4, 52, 0, 3, 37, 73, 19, 58, 11, 59, 11, 2, 24, 0, 0, 5, 5, 0, 2, 34, 3, 37, 58, 11, 59, 11,
    73, 19, 0, 0, 6, 52, 0, 2, 34, 3, 37, 58, 11, 59, 11, 73, 19, 0, 0, 7, 1, 1, 73, 19, 0, 0, 8,
    33, 0, 73, 19, 55, 11, 0, 0, 9, 38, 0, 73, 19, 0, 0, 10, 36, 0, 3, 37, 11, 11, 62, 11, 0, 0,
    11, 52, 0, 3, 37, 73, 19, 63, 25, 58, 11, 59, 11, 2, 24, 0, 0, 12, 52, 0, 3, 37, 73, 19, 58,
    11, 59, 11, 0, 0, 13, 15, 0, 73, 19, 0, 0, 14, 21, 1, 73, 19, 39, 25, 0, 0, 15, 5, 0, 73, 19,
    0, 0, 16, 24, 0, 0, 0, 17, 22, 0, 73, 19, 3, 37, 58, 11, 59, 11, 0, 0, 18, 4, 1, 73, 19, 3, 37,
    11, 11, 58, 11, 59, 5, 0, 0, 19, 40, 0, 3, 37, 28, 15, 0, 0, 20, 15, 0, 0, 0, 21, 19, 1, 3, 37,
    11, 11, 58, 11, 59, 5, 0, 0, 22, 13, 0, 3, 37, 73, 19, 58, 11, 59, 5, 56, 11, 0, 0, 0, 53, 1,
    0, 0, 5, 0, 1, 8, 0, 0, 0, 0, 1, 0, 12, 0, 1, 8, 0, 0, 0, 0, 0, 0, 0, 2, 2, 72, 0, 0, 0, 8, 0,
    0, 0, 12, 0, 0, 0, 2, 18, 7, 4, 2, 17, 7, 8, 3, 2, 72, 0, 0, 0, 1, 90, 19, 1, 6, 236, 0, 0, 0,
    4, 3, 110, 0, 0, 0, 1, 12, 2, 161, 0, 5, 0, 21, 1, 6, 240, 0, 0, 0, 6, 1, 22, 1, 8, 235, 0, 0,
    0, 6, 2, 23, 1, 9, 235, 0, 0, 0, 6, 3, 29, 1, 10, 236, 0, 0, 0, 0, 7, 122, 0, 0, 0, 8, 131, 0,
    0, 0, 16, 0, 9, 127, 0, 0, 0, 2, 4, 6, 1, 10, 5, 8, 7, 11, 6, 146, 0, 0, 0, 1, 16, 2, 161, 1,
    7, 127, 0, 0, 0, 8, 131, 0, 0, 0, 4, 0, 12, 7, 166, 0, 0, 0, 3, 172, 13, 171, 0, 0, 0, 14, 188,
    0, 0, 0, 15, 192, 0, 0, 0, 15, 197, 0, 0, 0, 16, 0, 2, 8, 5, 8, 13, 122, 0, 0, 0, 17, 205, 0,
    0, 0, 10, 2, 27, 2, 9, 7, 4, 18, 205, 0, 0, 0, 16, 4, 4, 55, 21, 19, 11, 0, 19, 12, 1, 19, 13,
    2, 19, 14, 3, 19, 15, 4, 0, 20, 2, 20, 5, 4, 13, 245, 0, 0, 0, 21, 28, 24, 4, 66, 21, 22, 22,
    197, 0, 0, 0, 4, 67, 21, 0, 22, 23, 197, 0, 0, 0, 4, 68, 21, 4, 22, 24, 197, 0, 0, 0, 4, 69,
    21, 8, 22, 25, 197, 0, 0, 0, 4, 71, 21, 12, 22, 26, 197, 0, 0, 0, 4, 72, 21, 16, 22, 27, 197,
    0, 0, 0, 4, 74, 21, 20, 0, 0, 124, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 37, 0, 0, 0, 86, 0, 0, 0,
    113, 0, 0, 0, 121, 0, 0, 0, 126, 0, 0, 0, 146, 0, 0, 0, 155, 0, 0, 0, 172, 0, 0, 0, 177, 0, 0,
    0, 190, 0, 0, 0, 196, 0, 0, 0, 208, 0, 0, 0, 217, 0, 0, 0, 226, 0, 0, 0, 233, 0, 0, 0, 246, 0,
    0, 0, 1, 1, 0, 0, 20, 1, 0, 0, 39, 1, 0, 0, 55, 1, 0, 0, 59, 1, 0, 0, 63, 1, 0, 0, 68, 1, 0, 0,
    77, 1, 0, 0, 87, 1, 0, 0, 103, 1, 0, 0, 118, 1, 0, 0, 133, 1, 0, 0, 140, 1, 0, 0, 85, 98, 117,
    110, 116, 117, 32, 99, 108, 97, 110, 103, 32, 118, 101, 114, 115, 105, 111, 110, 32, 49, 52,
    46, 48, 46, 48, 45, 49, 117, 98, 117, 110, 116, 117, 49, 0, 47, 103, 111, 47, 101, 98, 112,
    102, 45, 97, 112, 112, 115, 47, 114, 117, 115, 116, 47, 120, 100, 112, 112, 97, 115, 115, 47,
    115, 114, 99, 47, 98, 112, 102, 47, 120, 100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46, 99,
    0, 47, 103, 111, 47, 101, 98, 112, 102, 45, 97, 112, 112, 115, 47, 114, 117, 115, 116, 47, 120,
    100, 112, 112, 97, 115, 115, 0, 95, 95, 95, 95, 102, 109, 116, 0, 99, 104, 97, 114, 0, 95, 95,
    65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95, 95, 0, 95, 108, 105, 99, 101,
    110, 115, 101, 0, 98, 112, 102, 95, 116, 114, 97, 99, 101, 95, 112, 114, 105, 110, 116, 107, 0,
    108, 111, 110, 103, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 0, 95, 95,
    117, 51, 50, 0, 88, 68, 80, 95, 65, 66, 79, 82, 84, 69, 68, 0, 88, 68, 80, 95, 68, 82, 79, 80,
    0, 88, 68, 80, 95, 80, 65, 83, 83, 0, 88, 68, 80, 95, 84, 88, 0, 88, 68, 80, 95, 82, 69, 68,
    73, 82, 69, 67, 84, 0, 120, 100, 112, 95, 97, 99, 116, 105, 111, 110, 0, 68, 87, 95, 65, 84,
    69, 95, 117, 110, 115, 105, 103, 110, 101, 100, 95, 54, 52, 0, 68, 87, 95, 65, 84, 69, 95, 117,
    110, 115, 105, 103, 110, 101, 100, 95, 51, 50, 0, 120, 100, 112, 95, 112, 114, 111, 103, 95,
    115, 105, 109, 112, 108, 101, 0, 105, 110, 116, 0, 99, 116, 120, 0, 100, 97, 116, 97, 0, 100,
    97, 116, 97, 95, 101, 110, 100, 0, 100, 97, 116, 97, 95, 109, 101, 116, 97, 0, 105, 110, 103,
    114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 114, 120, 95, 113, 117, 101, 117,
    101, 95, 105, 110, 100, 101, 120, 0, 101, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100,
    101, 120, 0, 120, 100, 112, 95, 109, 100, 0, 112, 107, 116, 95, 115, 122, 0, 28, 0, 0, 0, 5, 0,
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 159, 235,
    1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 88, 1, 0, 0, 88, 1, 0, 0, 167, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 4, 24, 0, 0, 0, 8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0,
    0, 3, 0, 0, 0, 32, 0, 0, 0, 22, 0, 0, 0, 3, 0, 0, 0, 64, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 96,
    0, 0, 0, 48, 0, 0, 0, 3, 0, 0, 0, 128, 0, 0, 0, 63, 0, 0, 0, 3, 0, 0, 0, 160, 0, 0, 0, 78, 0,
    0, 0, 0, 0, 0, 8, 4, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 13, 6, 0, 0, 0, 97, 0, 0, 0, 1, 0, 0, 0, 101, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0,
    1, 105, 0, 0, 0, 1, 0, 0, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 9, 0, 0, 0, 93, 1, 0, 0, 0,
    0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 8, 0, 0, 0, 11, 0, 0, 0,
    16, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 118, 1, 0, 0, 0, 0, 0, 14, 10,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 9, 0, 0, 0, 11, 0, 0, 0, 4, 0, 0, 0,
    142, 1, 0, 0, 0, 0, 0, 14, 13, 0, 0, 0, 1, 0, 0, 0, 151, 1, 0, 0, 1, 0, 0, 15, 0, 0, 0, 0, 12,
    0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 159, 1, 0, 0, 1, 0, 0, 15, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0,
    0, 4, 0, 0, 0, 0, 120, 100, 112, 95, 109, 100, 0, 100, 97, 116, 97, 0, 100, 97, 116, 97, 95,
    101, 110, 100, 0, 100, 97, 116, 97, 95, 109, 101, 116, 97, 0, 105, 110, 103, 114, 101, 115,
    115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 114, 120, 95, 113, 117, 101, 117, 101, 95, 105,
    110, 100, 101, 120, 0, 101, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0,
    95, 95, 117, 51, 50, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 0, 99, 116,
    120, 0, 105, 110, 116, 0, 120, 100, 112, 95, 112, 114, 111, 103, 95, 115, 105, 109, 112, 108,
    101, 0, 120, 100, 112, 0, 47, 103, 111, 47, 101, 98, 112, 102, 45, 97, 112, 112, 115, 47, 114,
    117, 115, 116, 47, 120, 100, 112, 112, 97, 115, 115, 47, 115, 114, 99, 47, 98, 112, 102, 47,
    120, 100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46, 99, 0, 9, 118, 111, 105, 100, 32, 42,
    100, 97, 116, 97, 32, 61, 32, 40, 118, 111, 105, 100, 32, 42, 41, 40, 108, 111, 110, 103, 41,
    99, 116, 120, 45, 62, 100, 97, 116, 97, 59, 0, 9, 118, 111, 105, 100, 32, 42, 100, 97, 116, 97,
    95, 101, 110, 100, 32, 61, 32, 40, 118, 111, 105, 100, 32, 42, 41, 40, 108, 111, 110, 103, 41,
    99, 116, 120, 45, 62, 100, 97, 116, 97, 95, 101, 110, 100, 59, 0, 9, 105, 110, 116, 32, 112,
    107, 116, 95, 115, 122, 32, 61, 32, 100, 97, 116, 97, 95, 101, 110, 100, 32, 45, 32, 100, 97,
    116, 97, 59, 0, 9, 98, 112, 102, 95, 112, 114, 105, 110, 116, 107, 40, 34, 112, 97, 99, 107,
    101, 116, 32, 115, 105, 122, 101, 58, 32, 37, 100, 34, 44, 32, 112, 107, 116, 95, 115, 122, 41,
    59, 0, 9, 114, 101, 116, 117, 114, 110, 32, 88, 68, 80, 95, 80, 65, 83, 83, 59, 0, 99, 104, 97,
    114, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95, 95, 0, 120,
    100, 112, 95, 112, 114, 111, 103, 95, 115, 105, 109, 112, 108, 101, 46, 95, 95, 95, 95, 102,
    109, 116, 0, 95, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 111, 100, 97, 116, 97, 0, 108,
    105, 99, 101, 110, 115, 101, 0, 0, 159, 235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 20, 0,
    0, 0, 92, 0, 0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 121, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    7, 0, 0, 0, 16, 0, 0, 0, 121, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 125, 0, 0, 0, 174, 0, 0, 0, 34,
    32, 0, 0, 8, 0, 0, 0, 125, 0, 0, 0, 213, 0, 0, 0, 38, 36, 0, 0, 16, 0, 0, 0, 125, 0, 0, 0, 4,
    1, 0, 0, 24, 40, 0, 0, 24, 0, 0, 0, 125, 0, 0, 0, 35, 1, 0, 0, 2, 48, 0, 0, 56, 0, 0, 0, 125,
    0, 0, 0, 75, 1, 0, 0, 2, 52, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 255, 255, 255, 255, 4, 0, 8, 0, 8,
    124, 11, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 194, 0,
    0, 0, 5, 0, 8, 0, 155, 0, 0, 0, 8, 1, 1, 251, 14, 13, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1,
    31, 5, 0, 0, 0, 0, 27, 0, 0, 0, 35, 0, 0, 0, 60, 0, 0, 0, 79, 0, 0, 0, 3, 1, 31, 2, 15, 5, 30,
    5, 98, 0, 0, 0, 0, 246, 45, 175, 218, 253, 198, 224, 159, 75, 40, 116, 133, 83, 129, 62, 202,
    147, 0, 0, 0, 1, 246, 45, 175, 218, 253, 198, 224, 159, 75, 40, 116, 133, 83, 129, 62, 202,
    161, 0, 0, 0, 2, 184, 16, 242, 112, 115, 62, 16, 99, 25, 182, 126, 245, 18, 198, 36, 110, 172,
    0, 0, 0, 3, 173, 143, 243, 117, 81, 6, 181, 51, 180, 70, 21, 156, 65, 12, 89, 109, 190, 0, 0,
    0, 4, 90, 216, 188, 146, 93, 174, 30, 200, 123, 187, 4, 179, 20, 139, 24, 59, 0, 9, 2, 0, 0, 0,
    0, 0, 0, 0, 0, 24, 5, 34, 10, 19, 5, 38, 33, 5, 24, 33, 5, 2, 34, 75, 2, 2, 0, 1, 1, 47, 103,
    111, 47, 101, 98, 112, 102, 45, 97, 112, 112, 115, 47, 114, 117, 115, 116, 47, 120, 100, 112,
    112, 97, 115, 115, 0, 115, 114, 99, 47, 98, 112, 102, 0, 47, 117, 115, 114, 47, 105, 110, 99,
    108, 117, 100, 101, 47, 97, 115, 109, 45, 103, 101, 110, 101, 114, 105, 99, 0, 116, 97, 114,
    103, 101, 116, 47, 98, 112, 102, 47, 115, 114, 99, 47, 98, 112, 102, 0, 47, 117, 115, 114, 47,
    105, 110, 99, 108, 117, 100, 101, 47, 108, 105, 110, 117, 120, 0, 47, 103, 111, 47, 101, 98,
    112, 102, 45, 97, 112, 112, 115, 47, 114, 117, 115, 116, 47, 120, 100, 112, 112, 97, 115, 115,
    47, 115, 114, 99, 47, 98, 112, 102, 47, 120, 100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46,
    99, 0, 120, 100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46, 99, 0, 105, 110, 116, 45, 108,
    108, 54, 52, 46, 104, 0, 98, 112, 102, 95, 104, 101, 108, 112, 101, 114, 95, 100, 101, 102,
    115, 46, 104, 0, 98, 112, 102, 46, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 236, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    34, 0, 0, 0, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 3, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,
    13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 14, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 3, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 0, 0, 18, 0, 3, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 178, 0, 0, 0, 17, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 4, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 0, 0,
    0, 0, 3, 0, 0, 0, 6, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0, 21, 0, 0, 0, 0,
    0, 0, 0, 3, 0, 0, 0, 11, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 9, 0, 0, 0, 35, 0, 0, 0,
    0, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 12, 0, 0,
    0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 20, 0,
    0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 28,
    0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0,
    36, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0,
    0, 44, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0,
    0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8,
    0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0,
    8, 0, 0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0,
    0, 8, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 3, 0,
    0, 0, 8, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 3,
    0, 0, 0, 8, 0, 0, 0, 92, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0,
    3, 0, 0, 0, 8, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 104, 0, 0, 0, 0, 0,
    0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 108, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 112, 0, 0, 0,
    0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 116, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 120, 0,
    0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 124, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 8,
    0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 14, 0, 0, 0,
    24, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 80, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0,
    0, 104, 1, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 14, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2,
    0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
    2, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0,
    0, 2, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 3, 0,
    0, 0, 10, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 3,
    0, 0, 0, 12, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0,
    0, 3, 0, 0, 0, 12, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 50, 0, 0, 0, 0,
    0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 62, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 83, 0, 0,
    0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 125,
    0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 146, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 12, 0, 0,
    0, 170, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 13, 3, 14, 0, 46, 100, 101, 98, 117, 103,
    95, 97, 98, 98, 114, 101, 118, 0, 46, 116, 101, 120, 116, 0, 46, 114, 101, 108, 46, 66, 84, 70,
    46, 101, 120, 116, 0, 120, 100, 112, 95, 112, 114, 111, 103, 95, 115, 105, 109, 112, 108, 101,
    46, 95, 95, 95, 95, 102, 109, 116, 0, 46, 100, 101, 98, 117, 103, 95, 108, 111, 99, 108, 105,
    115, 116, 115, 0, 46, 114, 101, 108, 46, 100, 101, 98, 117, 103, 95, 115, 116, 114, 95, 111,
    102, 102, 115, 101, 116, 115, 0, 46, 100, 101, 98, 117, 103, 95, 115, 116, 114, 0, 46, 100,
    101, 98, 117, 103, 95, 108, 105, 110, 101, 95, 115, 116, 114, 0, 46, 114, 101, 108, 46, 100,
    101, 98, 117, 103, 95, 97, 100, 100, 114, 0, 46, 114, 101, 108, 120, 100, 112, 0, 46, 114, 101,
    108, 46, 100, 101, 98, 117, 103, 95, 105, 110, 102, 111, 0, 46, 108, 108, 118, 109, 95, 97,
    100, 100, 114, 115, 105, 103, 0, 95, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 101, 108,
    46, 100, 101, 98, 117, 103, 95, 108, 105, 110, 101, 0, 46, 114, 101, 108, 46, 100, 101, 98,
    117, 103, 95, 102, 114, 97, 109, 101, 0, 120, 100, 112, 95, 112, 114, 111, 103, 95, 115, 105,
    109, 112, 108, 101, 0, 120, 100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46, 99, 0, 46, 115,
    116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97, 98, 0, 46, 114, 111, 100, 97, 116, 97, 0,
    46, 114, 101, 108, 46, 66, 84, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 250, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 243, 15, 0, 0, 0, 0, 0, 0, 27, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 0, 0, 0, 9, 0, 0, 0, 64,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 12, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0,
    26, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 10, 1, 0, 0, 1, 0, 0,
    0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 179, 0, 0, 0, 1,
    0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 156, 0, 0, 0, 0, 0, 0, 0, 76, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 0, 0, 0, 0, 0, 0, 0, 14,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    152, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 246, 1, 0, 0, 0, 0,
    0, 0, 57, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 148, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 12, 0,
    0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0,
    0, 0, 0, 0, 0, 0, 78, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47,
    3, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 74, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 144, 12, 0, 0, 0, 0, 0, 0, 224, 1, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 11, 0, 0, 0, 8, 0, 0, 0,
    0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 97, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 175, 3, 0, 0, 0, 0, 0, 0, 147, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 66, 5, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 124, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 14, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0,
    14, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 22, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 5, 0, 0, 0, 0, 0, 0, 23, 3, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 1, 0, 0, 9, 0, 0, 0, 64,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 14, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0,
    0, 26, 0, 0, 0, 16, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 124, 8, 0, 0, 0, 0, 0, 0, 144, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0,
    0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 14, 0, 0, 0, 0, 0, 0,
    96, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 18, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0,
    0, 0, 207, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 9, 0, 0, 0,
    0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 203, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 15,
    0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0,
    16, 0, 0, 0, 0, 0, 0, 0, 191, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 56, 9, 0, 0, 0, 0, 0, 0, 198, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 187, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 64, 15, 0, 0, 0, 0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 22, 0, 0, 0, 8, 0, 0,
    0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 254, 9, 0, 0, 0, 0, 0, 0, 196, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 164, 0, 0, 0, 3, 76, 255, 111, 0, 0, 0, 128,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 15, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 26, 0,
    0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 2, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 10, 0, 0, 0, 0, 0, 0, 104, 1, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 13, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0,
];