fn main() {
    tonic_build::compile_protos("relay.proto").unwrap();
}
