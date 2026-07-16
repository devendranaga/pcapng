pub mod pcapng;

#[cfg(test)]
mod tests {
    use super::*;
    use pcapng;

    fn read_callback(epb : &mut pcapng::enhanced_pkt_block) {
        println!("Enhanced Packet Block:");
        println!("\tCaptured packet Length: {}", epb.captured_len);
        println!("\tOriginal packet Length: {}", epb.original_len);
        println!("\tPacket Length: {}", epb.packet_data.len());
    }

    #[test]
    fn test_pcapng_no_options() {
        let mut p_handle = pcapng::pcapng_parser::new();
        let res = p_handle.parse("tests/test_no_options.pcapng".to_string(), read_callback);
        if res != 0 {
            panic!("invalid pcapng file");
        }
        p_handle.close();
    }
}
