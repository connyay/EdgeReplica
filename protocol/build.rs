fn main() {
    connectrpc_build::Config::new()
        .files(&["../proto/edgereplica/admin/v1/admin.proto"])
        .includes(&["../proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("failed to compile protos");
}
