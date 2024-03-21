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
    unsafe fn as_ref<'a, T: RawPtr>(addr: usize) -> &'a T {
        &*(addr as *const T)
    }

    /// # Safety
    ///
    /// When calling this method, you have to ensure that all of the following is true:
    ///
    /// * The pointer must point to an initialized instance of `T`.
    ///
    /// * You must enforce Rust's aliasing rules
    unsafe fn as_mut<'a, T: RawPtr>(addr: usize) -> &'a mut T {
        &mut *(addr as *mut T)
    }

    fn addr(&self) -> usize {
        let ptr: *const Self = self;
        ptr as usize
    }
}

pub mod raw_ptr {
    /// `SafetyChecked` Trait
    ///
    /// This trait signifies that certain safety checks
    /// can be automatically performed by the code itself.
    ///
    /// Implementing this trait indicates that the associated functionality
    /// has been designed to undergo automatic safety verification processes,
    /// minimizing the need for manual intervention.
    ///
    /// It is particularly useful for encapsulating operations
    /// that can be safely abstracted away from direct `unsafe` code usage.
    ///
    /// Types implementing `SafetyChecked` should ensure
    /// that all potential safety risks are either inherently
    /// mitigated by the implementation or are automatically checkable at compile or run time.
    pub trait SafetyChecked: super::RawPtr {
        fn is_not_null(&self) -> bool {
            let ptr: *const Self = self;
            !ptr.is_null()
        }

        fn is_aligned(&self) -> bool {
            self.addr() % core::mem::align_of::<usize>() == 0
        }

        fn has_permission(&self) -> bool;
    }

    /// `SafetyAssured` Trait
    ///
    /// The `SafetyAssured` trait is intended
    /// to be used as a marker for code sections
    /// where safety cannot be automatically checked
    /// or guaranteed by the compiler or runtime environment.
    /// Instead, the safety of operations marked with this trait relies on manual checks
    /// and guarantees provided by the developer.
    ///
    /// Implementing `SafetyAssured` serves
    /// as a declaration that the developer has manually reviewed
    /// the associated operations and is confident in their safety,
    /// despite the inability to enforce these guarantees automatically.
    /// It is a commitment to adhering to Rust's safety principles
    /// while working within the necessary confines of `unsafe` code.
    pub trait SafetyAssured {
        fn initialized(&self) -> bool;
        fn lifetime(&self) -> bool;
        fn ownership(&self) -> bool;
    }

    pub fn assume<T: SafetyChecked + SafetyAssured>(addr: usize) -> Option<SafetyAssumed> {
        let ptr = addr as *const T;
        // Safety: This cast from a raw pointer to a reference is considered safe
        //         because it is used solely for the purpose of verifying alignment and range,
        //         without actually dereferencing the pointer.
        let ref_ = unsafe { &*(ptr) };
        let checked = ref_.is_not_null() && ref_.is_aligned() && ref_.has_permission();
        let assured = ref_.initialized() && ref_.lifetime() && ref_.ownership();

        match checked && assured {
            true => Some(SafetyAssumed { addr }),
            false => None,
        }
    }

    pub struct SafetyAssumed {
        addr: usize,
    }

    impl SafetyAssumed {
        /// Provides safe access to a target structure
        /// by ensuring that `SafetyChecked` and `SafetyAssured` traits are implemented.
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
            T: SafetyChecked + SafetyAssured,
            F: Fn(&T) -> R,
        {
            unsafe {
                let obj = T::as_ref(self.addr);
                f(obj)
            }
        }

        /// Provides safe mutation to a target structure
        /// by ensuring that `SafetyChecked` and `SafetyAssured` traits are implemented.
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
            T: SafetyChecked + SafetyAssured,
            F: FnMut(&mut T) -> R,
        {
            unsafe {
                let obj = T::as_mut(self.addr);
                f(obj)
            }
        }
    }
}
