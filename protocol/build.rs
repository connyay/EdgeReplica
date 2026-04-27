fn main() {
    connectrpc_build::Config::new()
        .files(&[
            "../proto/edgereplica/admin/v1/admin.proto",
            "../proto/edgereplica/sync/v1/sync.proto",
        ])
        .includes(&["../proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("failed to compile protos");
}
