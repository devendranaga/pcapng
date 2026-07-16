#![allow(non_camel_case_types)]
#![allow(dead_code)]

// constants
const SHB_BLOCK_MAGIC           : [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
const SHB_BYTE_ORDER_MAGIC_BE   : [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];
const SHB_BYTE_ORDER_MAGIC_LE   : [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];

const SHB_OP_COMMENT    : u16 = 1;
const SHB_OP_HW         : u16 = 2;
const SHB_OP_OS         : u16 = 3;
const SHB_OP_USER_APP   : u16 = 4;

const SHB_INTF_DESC_BLOCK   : u32 = 1;
const SHB_INTF_STATS_BLOCK  : u32 = 5;
const SHB_ENH_PKT_BLOCK     : u32 = 6;

const SHB_OPT_COMMENT   : u32 = 0x00000001;
const SHB_OPT_HW        : u32 = 0x00000002;
const SHB_OPT_OS        : u32 = 0x00000004;
const SHB_OPT_USER_APP  : u32 = 0x00000008;

/// SHB header
struct pcapng_shb {
    block_type          : u32,
    total_len           : u32,
    byte_order_magic    : u32,
    major_version       : u16,
    minor_version       : u16,
    section_len         : u64,
}

impl pcapng_shb {
    fn new() -> Self {
        Self {
            block_type          : 0,
            total_len           : 0,
            byte_order_magic    : 0,
            major_version       : 0,
            minor_version       : 0,
            section_len         : 0,
        }
    }
}

pub struct enhanced_pkt_block {
    pub intf_id         : u32,
    pub ts_high         : u32,
    pub ts_low          : u32,
    pub captured_len    : u32,
    pub original_len    : u32,
    pub packet_data     : Vec<u8>,
}

impl enhanced_pkt_block {
    pub fn new() -> Self {
        Self {
            intf_id         : 0,
            ts_high         : 0,
            ts_low          : 0,
            captured_len    : 0,
            original_len    : 0,
            packet_data     : Vec::new(),
        }
    }
}

pub struct intf_stats_block {
    pub intf_id         : u32,
    pub timestamp       : u64,
    pub comment         : String,
    pub start_time      : u64,
    pub end_time        : u64,
    pub pkts_rx         : u64,
    pub pkts_dropped    : u64,
}

impl intf_stats_block {
    pub fn new() -> Self {
        Self {
            intf_id         : 0,
            timestamp       : 0,
            comment         : String::new(),
            start_time      : 0,
            end_time        : 0,
            pkts_rx         : 0,
            pkts_dropped    : 0,
        }
    }
}

pub struct pcapng {
    handle          : i32,
    total_len       : u32,
    shb_hdr         : pcapng_shb,
    pkt_buffer      : [u8; 4096],
    shb_opts        : u32,
    hw              : Vec<u8>,
    os              : Vec<u8>,
    application     : Vec<u8>,
    comment         : Vec<u8>,
    link_type       : u16,
    snaplen         : u32,
    ifname          : String,
    ts_resol        : u16,
    os_str          : String,
    big_endian      : bool,
    offset          : usize,
    stats           : intf_stats_block,
}

impl pcapng {
    pub fn new() -> Self {
        Self {
            handle          : -1,
            total_len       : 0,
            shb_hdr         : pcapng_shb::new(),
            pkt_buffer      : [0; 4096],
            shb_opts        : 0,
            hw              : Vec::new(),
            os              : Vec::new(),
            application     : Vec::new(),
            comment         : Vec::new(),
            link_type       : 0,
            snaplen         : 0,
            ifname          : String::new(),
            ts_resol        : 0,
            os_str          : String::new(),
            big_endian      : false,
            offset          : 0,
            stats           : intf_stats_block::new(),
        }
    }

    fn get_u16(&mut self) -> u16 {
        let u16_val : u16;

        if self.big_endian {
            u16_val = ((self.pkt_buffer[self.offset] as u16) << 8) |
                        self.pkt_buffer[self.offset + 1] as u16;
        } else {
            u16_val = ((self.pkt_buffer[self.offset + 1] as u16) << 8) |
                        self.pkt_buffer[self.offset] as u16;
        }
        self.offset += 2;
        return u16_val;
    }

    fn get_u32(&mut self) -> u32 {
        let u32_val : u32;

        if self.big_endian {
            u32_val = ((self.pkt_buffer[self.offset] as u32) << 24)     |
                      ((self.pkt_buffer[self.offset + 1] as u32) << 16) |
                      ((self.pkt_buffer[self.offset + 2] as u32) << 8)  |
                        self.pkt_buffer[self.offset + 3] as u32;
        } else {
            u32_val = ((self.pkt_buffer[self.offset + 3] as u32) << 24) |
                      ((self.pkt_buffer[self.offset + 2] as u32) << 16) |
                      ((self.pkt_buffer[self.offset + 1] as u32) << 8)  |
                        self.pkt_buffer[self.offset] as u32;
        }
        self.offset += 4;
        return u32_val;
    }

    fn get_str(&mut self, len : usize) -> String {
        let str_val = String::from_utf8(self.pkt_buffer[self.offset..self.offset + len].to_vec()).unwrap();
        self.offset += len;

        return str_val;
    }

    fn get_u64(&mut self) -> u64 {
        let u64_bytes : [u8; 8] = self.pkt_buffer[self.offset..self.offset + 8].
                                                    try_into().
                                                    expect("Buffer is shorter than 8 bytes");
        let u64_val : u64;

        if self.big_endian {
            u64_val = u64::from_be_bytes(u64_bytes);
        } else {
            u64_val = u64::from_le_bytes(u64_bytes);
        }
        self.offset += 8;
        return u64_val;
    }

    fn parse_options(&mut self) -> i32 {
        let mut option : u16;
        let mut option_len : u16;

        loop {
            unsafe {
                let mut res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, 4);
                if res != 4 {
                    println!("invalid read length {}", res);
                    return -1;
                }

                self.offset = 0;

                let val_32 = self.get_u32();
                if val_32 == self.shb_hdr.total_len {
                    return 1;
                }

                if (self.pkt_buffer[0] == 0) &&
                   (self.pkt_buffer[1] == 0) &&
                   (self.pkt_buffer[2] == 0) &&
                   (self.pkt_buffer[3] == 0) {
                    return 0;
                }

                option = self.get_u16();
                option_len = self.get_u16();
                let original_option_len = option_len as usize;

                // calculate pad bytes
                if option_len % 4 != 0 {
                    option_len = (option_len + 3) & !3;
                }

                self.offset = 0;

                // read including pad bytes which added afterwards
                res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, option_len as usize);
                if res != option_len.try_into().unwrap() {
                    println!("invalid read length {}", res);
                    return -1;
                }

                match option {
                    SHB_OP_HW => {
                        self.hw = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_HW;
                    },
                    SHB_OP_OS => {
                        self.os = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_OS;
                    },
                    SHB_OP_USER_APP => {
                        self.application = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_USER_APP;
                    },
                    SHB_OP_COMMENT => {
                        self.comment = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_COMMENT;
                    },
                    _ => {
                        println!("cannot parse option {}", option);
                        return -1;
                    }
                }
            }
        }
    }

    fn parse_intf_desc_block(&mut self, block_total_len : u32) -> isize {
        const SHB_IDB_OPT_IFNAME : u16 = 2;
        const SHB_IDB_OPT_TSRESOL : u16 = 9;
        const SHB_IDB_OPT_OS : u16 = 12;

        unsafe {
            self.offset = 0;
            let res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, block_total_len as usize);
            if res != block_total_len as isize {
                println!("invalid read length");
                return -1;
            }

            self.link_type = self.get_u16();
            self.offset += 2;
            self.snaplen = self.get_u32();

            let val_32 = self.get_u32();
            if val_32 == block_total_len + 8 {
                println!("end of ISB with no options");
                return 0;
            } else {
                self.offset -= 4;
            }
            loop {
                let opt_name = self.get_u16();
                let opt_len = self.get_u16();

                if opt_name == 0 && opt_len == 0 {
                    let block_bytes = self.get_u32();
                    if block_total_len + 8 != block_bytes {
                        println!("block total len {} != block end bytes {}", block_total_len, block_bytes);
                        return -1;
                    }
                    return 0;
                }
                match opt_name {
                    SHB_IDB_OPT_IFNAME => {
                        self.ifname = self.get_str(opt_len as usize);
                    },
                    SHB_IDB_OPT_TSRESOL => {
                        self.ts_resol = self.pkt_buffer[self.offset] as u16;
                        self.offset += 1;
                    },
                    SHB_IDB_OPT_OS => {
                        self.os_str = self.get_str(opt_len as usize);
                    },
                    _ => (),
                }
                if opt_len % 4 != 0 {
                   let remaining_len = (opt_len + 3) & !3;
                    self.offset += (remaining_len - ((opt_len + 3) & !3)) as usize;
                }
            }
        }
    }

    fn parse_enhanced_pkt_block(&mut self, epb : &mut enhanced_pkt_block, block_total_len : u32) -> isize {
        unsafe {
            self.offset = 0;
            let res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, block_total_len as usize);
            if res != block_total_len as isize {
                println!("invalid enhanced packet block");
                return res;
            }

            epb.intf_id         = self.get_u32();
            epb.ts_high         = self.get_u32();
            epb.ts_low          = self.get_u32();
            epb.captured_len    = self.get_u32();
            epb.original_len    = self.get_u32();

            epb.packet_data.extend_from_slice(&self.pkt_buffer[self.offset..self.offset + epb.captured_len as usize]);

            self.offset += epb.captured_len as usize;
            let pad;

            if epb.captured_len % 4 != 0 {
                pad = ((epb.captured_len + 3) & !3) - epb.captured_len;
                self.offset += pad as usize;
            }

            let block_bytes = self.get_u32();
            if block_total_len + 8 != block_bytes {
                println!("EPB end length {} does not match with set EPB length {}",
                                block_bytes, block_total_len);
                return -1;
            }
        }
        0
    }

    fn parse_intf_stats_block(&mut self, block_total_len : u32) -> isize {
        const ISB_OPT_COMMENT       : u16 = 1;
        const ISB_OPT_START_TIME    : u16 = 2;
        const ISB_OPT_END_TIME      : u16 = 3;
        const ISB_OPT_PKT_RECV      : u16 = 4;
        const ISB_OPT_PKT_DROP      : u16 = 5;

        unsafe {
            self.offset = 0;
            let res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, block_total_len as usize);
            if res != block_total_len as isize {
                println!("invalid read length {}", res);
                return res;
            }

            self.stats.intf_id = self.get_u32();

            self.stats.timestamp = self.get_u64();

            loop {
                let option_type = self.get_u16();
                let option_len = self.get_u16();

                if option_type == 0 && option_len == 0 {

                    let block_bytes = self.get_u32();
                    if block_total_len + 8 != block_bytes {
                        println!("block_total_len {} != block_bytes {}", block_total_len, block_bytes);
                        return -1;
                    }
                    return 0;
                }

                match option_type {
                    ISB_OPT_COMMENT => {
                        self.stats.comment = self.get_str(option_len as usize);
                    },
                    ISB_OPT_START_TIME => {
                        self.stats.start_time = self.get_u64();
                    },
                    ISB_OPT_END_TIME => {
                        self.stats.end_time = self.get_u64();
                    },
                    ISB_OPT_PKT_RECV => {
                        self.stats.pkts_rx = self.get_u64();
                    },
                    ISB_OPT_PKT_DROP => {
                        self.stats.pkts_dropped = self.get_u64();
                    },
                    _ => {
                        println!("Invalid ISB option {}", option_type);
                        return -1;
                    }
                }
                if option_len % 4 != 0 {
                    let pad = (option_len + 3) & !3;
                    self.offset += pad as usize;
                }
            }
        }
    }

    fn parse_blocks(&mut self, read_callback : fn(epb : &mut enhanced_pkt_block)) -> isize {
        loop {
            unsafe {
                self.offset = 0;

                let mut res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, 8 as usize);
                if res == 0 {
                    println!("finished reading");
                    return 0;
                } else if res != 8 {
                    println!("invalid read length of block data");
                    return -1;
                }

                let block_name = self.get_u32();

                if block_name == 0 {
                    return 0;
                }

                let block_total_len = self.get_u32();

                match block_name {
                    SHB_INTF_DESC_BLOCK => {
                        res = self.parse_intf_desc_block(block_total_len - 8);
                        if res != 0 {
                            println!("invalid IDB block");
                            return res;
                        }
                    },
                    SHB_ENH_PKT_BLOCK => {
                        let mut epb : enhanced_pkt_block = enhanced_pkt_block::new();

                        res = self.parse_enhanced_pkt_block(&mut epb, block_total_len - 8);
                        if res != 0 {
                            println!("invalid ENH block");
                            return res;
                        }
                        read_callback(&mut epb);
                    },
                    SHB_INTF_STATS_BLOCK => {
                        res = self.parse_intf_stats_block(block_total_len - 8);
                        if res != 0 {
                            println!("invalid ISB block");
                        }
                    }
                    _ => {
                        println!("unknown parser block {}", block_name);
                        return -1;
                    }
                }
            }
        }
    }

    pub fn open(&mut self, filename : String, read_callback : fn(epb : &mut enhanced_pkt_block)) -> i32 {
        unsafe {
            self.handle = libc::open(filename.as_ptr() as *const i8, libc::O_RDONLY);
            if self.handle == -1 {
                println!("failed to open {}", filename);
                return -1;
            }

            // read the header
            let res = libc::read(self.handle,
                                 self.pkt_buffer.as_ptr()
                                    as *mut libc::c_void, 24);
            if res != 24 {
                println!("invalid read length {}", res);
                return -1;
            }

            // validate section header length
            if self.pkt_buffer[..4] != SHB_BLOCK_MAGIC[..4] {
                println!("invalid section header magic");
                return -1;
            }

            // determine the packet endian-ness
            if self.pkt_buffer[8..12] == SHB_BYTE_ORDER_MAGIC_BE[..4] {
                self.big_endian = true;
            } else if self.pkt_buffer[8..12] == SHB_BYTE_ORDER_MAGIC_LE[..4] {
                self.big_endian = false;
            } else {
                println!("invalid byte order or unknown byte magic");
                return -1;
            }

            // go back and read the total length now that we know endian
            self.offset = 4;
            self.shb_hdr.total_len = self.get_u32();

            // start reading the version and section header length
            self.offset = 12;
            self.shb_hdr.major_version = self.get_u16();
            self.shb_hdr.minor_version = self.get_u16();
            self.shb_hdr.section_len = self.get_u64();

            // parse shb options
            let res = self.parse_options();
            println!("res {}", res);
            if res == -1 {
                println!("invalid options\n");
                return -1;
            } else if res == 0 { // has valid options, so read the length and match it
                self.offset = 0;
                let res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, 4 as usize);
                if res != 4 {
                    println!("invalid read size\n");
                    return -1;
                }

                self.total_len = self.get_u32();
                if self.shb_hdr.total_len != self.total_len {
                    println!("incorrectly formatted SHB\n");
                }
            } // value 1 means options are not there and length is already parsed out.

            // parse remaining blocks
            return self.parse_blocks(read_callback).try_into().unwrap();
        }
    }
}

