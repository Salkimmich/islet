#![warn(rust_2018_idioms)]
#![deny(warnings)]
#![no_std]

//! # Safe Abstraction Crate
//!
//! The `safe_abstraction` crate is a library designed
//! to facilitate safer abstraction over `unsafe` code.
//!
//! Its primary goal is to enhance the safety of `unsafe` code
//! by providing data structures and functions that minimize
//! the need for direct `unsafe` code usage,
//! and by offering traits for automating
//! and explicitly marking parts of `unsafe` code
//! that require developer intervention.
//!
//! ## Features
//!
//! - **Encapsulation of Unsafe Code**: Offers a way to safely abstract `unsafe` operations, allowing for lower-level operations like memory access to be performed more safely.
//!
//! - **Runtime Safety Checks**: Provides methods to perform crucial safety checks at runtime, such as verifying if a pointer is null and checking whether a pointer is properly aligned. These checks happen when the methods are called during the execution of a program.
//!
//! - **Compile-Time Type Safety Checks**: Enforces certain safety guarantees at compile time. For example, the use of Rust's type system can ensure that only pointers to types with known sizes are used, leveraging the `Sized` trait bound.
//!
//! - **Developer-Driven Safety Verification**: Introduces traits that allow developers to explicitly mark parts of `unsafe` code that still require manual safety guarantees, making it clear which parts of the code need careful review.

pub trait RawPtr: Sized {
    /// # Safety
    ///
    /// When calling this method, you have to ensure that all of the following is true:
    ///
    /// * The pointer must point to an initialized instance of `T`.
    ///
    /// * You must enforce Rust's aliasing rules
    unsafe fn as_ref<'a, T: RawPtr>(addr: usize) -> Option<&'a T> {
        match Self::is_valid::<T>(addr) {
            true => Some(&*(addr as *const T)),
            false => None,
        }
    }

    /// # Safety
    ///
    /// When calling this method, you have to ensure that all of the following is true:
    ///
    /// * The pointer must point to an initialized instance of `T`.
    ///
    /// * You must enforce Rust's aliasing rules
    unsafe fn as_unchecked_ref<'a, T: RawPtr>(addr: usize) -> &'a T {
        &*(addr as *const T)
    }

    /// # Safety
    ///
    /// When calling this method, you have to ensure that all of the following is true:
    ///
    /// * The pointer must point to an initialized instance of `T`.
    ///
    /// * You must enforce Rust's aliasing rules
    unsafe fn as_mut<'a, T: RawPtr>(addr: usize) -> Option<&'a mut T> {
        match Self::is_valid::<T>(addr) {
            true => Some(&mut *(addr as *mut T)),
            false => None,
        }
    }

    /// # Safety
    ///
    /// When calling this method, you have to ensure that all of the following is true:
    ///
    /// * The pointer must point to an initialized instance of `T`.
    ///
    /// * You must enforce Rust's aliasing rules
    unsafe fn as_unchecked_mut<'a, T: RawPtr>(addr: usize) -> &'a mut T {
        &mut *(addr as *mut T)
    }

    fn is_valid<T: RawPtr>(addr: usize) -> bool {
        let ptr = addr as *const T;
        // Safety: This cast from a raw pointer to a reference is considered safe
        //         because it is used solely for the purpose of verifying alignment and range,
        //         without actually dereferencing the pointer.
        let ref_ = unsafe { &*(ptr) };
        !ptr.is_null() && ref_.is_aligned() && ref_.has_permission()
    }

    fn addr(&self) -> usize {
        let ptr: *const Self = self;
        ptr as usize
    }

    fn is_aligned(&self) -> bool {
        self.addr() % core::mem::align_of::<usize>() == 0
    }

    fn has_permission(&self) -> bool;
}

pub mod raw_ptr {
    pub fn verify<T: super::RawPtr + DeveloperAssured>(addr: usize) -> Option<Verified> {
        match T::is_valid::<T>(addr) {
            true => Some(Verified { addr }),
            false => None,
        }
    }

    pub struct Verified {
        addr: usize,
    }

    impl Verified {
        /// Provides safe access to a target structure
        /// by ensuring that `RawPtr` and `DeveloperAssured` traits are implemented.
        ///
        /// # Safety
        /// This function facilitates safe interaction
        /// with structures accessed through raw pointers by leveraging
        /// the Rust's safety guarantees built upon
        /// the assumption that developers ensure the safety of `unsafe` code.
        ///
        /// # TODO: Checked the claim below by MIRI
        /// However, `unsafe` code passed through a closure,
        /// it becomes a subject for analysis at the MIR (Mid-level Intermediate Representation) stage.
        /// This allows for further security enhancements
        /// through the use of `unsafe` code analysis tools.
        ///
        /// # Caution
        /// It's important to remember that while this function aims
        /// to provide a safer interface for interacting with `unsafe` code,
        /// the inherent risks associated with `unsafe` code cannot be entirely eliminated.
        /// Developers are encouraged to use `unsafe` analysis tools
        /// to strengthen security and ensure that all
        /// safety guarantees are thoroughly verified.
        pub fn with<T, F, R>(&self, f: F) -> R
        where
            T: super::RawPtr + DeveloperAssured,
            F: Fn(&T) -> R,
        {
            unsafe {
                let obj = T::as_unchecked_ref(self.addr);
                f(obj)
            }
        }

        /// Provides safe mutation to a target structure
        /// by ensuring that `RawPtr` and `DeveloperAssured` traits are implemented.
        ///
        /// # Safety
        /// This function facilitates safe interaction
        /// with structures accessed through raw pointers by leveraging
        /// the Rust's safety guarantees built upon
        /// the assumption that developers ensure the safety of `unsafe` code.
        ///
        /// # TODO: Checked the claim below by MIRI
        /// However, `unsafe` code passed through a closure,
        /// it becomes a subject for analysis at the MIR (Mid-level Intermediate Representation) stage.
        /// This allows for further security enhancements
        /// through the use of `unsafe` code analysis tools.
        ///
        /// # Caution
        /// It's important to remember that while this function aims
        /// to provide a safer interface for interacting with `unsafe` code,
        /// the inherent risks associated with `unsafe` code cannot be entirely eliminated.
        /// Developers are encouraged to use `unsafe` analysis tools
        /// to strengthen security and ensure that all
        /// safety guarantees are thoroughly verified.
        pub fn mut_with<T, F, R>(&self, mut f: F) -> R
        where
            T: super::RawPtr + DeveloperAssured,
            F: FnMut(&mut T) -> R,
        {
            unsafe {
                let obj = T::as_unchecked_mut(self.addr);
                f(obj)
            }
        }
    }

    pub trait DeveloperAssured {
        fn initialized(&self) -> bool;
        fn lifetime(&self) -> bool;
        fn ownership(&self) -> bool;
    }
}
