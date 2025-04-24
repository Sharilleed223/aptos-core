module 0xc0ffee::m {
    struct Func(|| ||u64) has copy, drop;

    public fun test(): u64 {
        let f = Func(|| ||42);
        f()()
    }
}
