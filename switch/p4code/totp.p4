/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>
/**
../../install/bin/bf-p4c --std p4-16 --target tofino --arch tna --bf-rt-schema tofino/bf-rt.json -o /home/tangyunyi/p4sde/bf-sde-9.7.0/test/bier/tofino -g /home/tangyunyi/p4sde/bf-sde-9.7.0/test/bier/BIER.p4

/home/jia/bf-sde-9.7.0/install/bin/bf-p4c --std p4-16 --target tofino --arch tna --bf-rt-schema /home/jia/bf-sde-9.7.0/totp/tofino/bf-rt.json -o /home/jia/bf-sde-9.7.0/totp/tofino -g totp.p4
**/

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;

/* Table Sizes */
const int IPV4_HOST_SIZE = 65536;
const int IPV4_LPM_SIZE  = 12288;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header Ethernet{
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         ethernetType;
}


header IPv6{
    bit<4>      version;
    bit<8>      class;
    bit<20>     flowLabel;
    bit<16>     payloadLength;
    bit<8>      nextHeader;
    bit<8>      hopLimit;
    IPv6Address srcAddr;
    IPv6Address dstAddr;
}

header AH_h{
    bit<8>  nextHeader;         //4:IPv4  41:IPv6   143:Ethernet
    bit<8>  payloadLength;
    bit<16> reserved;       
    bit<32> spi;                //Security Parameters Index (SPI)
    bit<32> seq;                //Sequence Number Field
    bit<64> icv;                //Integrity Check Value-ICV (variable)
}

header inthdr_h {
    bit<8>  device_no;
    bit<9>  ingress_port;
    bit<9>  egress_port;
    bit<48> ingress_global_timestamp;
    bit<32> enq_timestamp;
    bit<19> enq_qdepth;
    bit<32> deq_timedelta;
    bit<19> deq_qdepth;  
}

header UDP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udpLength;
    bit<16> checksum;
}

header ICMPv6_h{
   bit<8>   type;
   bit<8>   code;
   bit<16>  checksum;
   bit<32>  reserved;
   bit<128> targetAddress;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t{
    Ethernet    ethernet;
    IPv6        ipv6;
    ICMPv6_h    icmpv6;
    AH_h        ah;
    UDP_h       udp;
    inthdr_h    inthdr;

}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    // bit<10> mirror_session;
    //bitstring bitstring;
    //bitstring[4] bitstring;       
    
    
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType) {
            0x86dd:parse_ipv6;
            default:accept;
        }
    }
    state parse_ipv6{
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            51:parse_ah;
            17:parse_udp;
            58:parse_icmpv6;
            default:accept;
        }
    }
    
    state parse_icmpv6{
       pkt.extract(hdr.icmpv6);
       transition accept;
   }

   state parse_ah{
       pkt.extract(hdr.ah);
       transition select(hdr.ah.nextHeader){
           17:parse_udp;
           default:accept;
       }
   }
    
   state parse_udp{
       pkt.extract(hdr.udp);
       transition accept;
   }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{   
action forward (bit<9> port){
    ig_tm_md.ucast_egress_port = port;
}

// action add_bier(bit<8> bitstring, bit<9> port){
//     hdr.bier.setValid();
//     hdr.bs.setValid();
//     hdr.bs.bitstring = bitstring;
//     hdr.ipv6.nextheader = 60;
//     hdr.bier.extlength = 29;
//     hdr.ipv6.payloadlength = hdr.ipv6.payloadlength +29;
//     hdr.bier.optiontype = 0x11;
//     hdr.bier.optionlength = 26;
//     hdr.bier.nextheader = 59;       //不确定负载为什么类型
//     ig_tm_md.ucast_egress_port = port;
//     //ig_tm_md.ucast_egress_port = 192;

// }

// action del_bier(bit<9> port){
//     hdr.ipv6.nextheader = hdr.bier.nextheader;
//     hdr.bier.setInvalid();
//     hdr.bs.setInvalid();
//     ig_tm_md.ucast_egress_port = port;
//     hdr.ipv6.payloadlength = hdr.ipv6.payloadlength -29;
//     //ig_tm_md.ucast_egress_port = 192;  //recirculate

// }  

action _drop(){
    ig_dprsr_md.drop_ctl = 1;
}

action totp_implement(bit<32> totp_code, bit<9> port){
    hdr.ah.setValid();
    hdr.ah.seq = totp_code; // totp
    hdr.ah.nextHeader = 17;
    hdr.ah.payloadLength = 20;
    hdr.ipv6.nextHeader = 51;
    hdr.ipv6.payloadLength = hdr.ipv6.payloadLength + 20;
    hdr.ah.reserved = 0;
    hdr.ah.spi = 456;
    hdr.ah.icv = 0;
    ig_tm_md.ucast_egress_port = port;
} 

action send_ipv6(bit<9> port) {
    ig_tm_md.ucast_egress_port = port;
}

// table encap{    //插入BIER头
//     actions = {
//         add_bier;
//         _drop;
//     }
//     key = {
//         hdr.ipv6.dstAddr:   exact;
//     }
//     size = 1024;
//     //default_action = _drop;
// }

// table decap{    //去掉BIER头
//     actions = {
//         del_bier;
        
//         _drop;
//     }
//     key = {
//         hdr.ipv6.dstAddr:   exact;
//         //hdr.bs.bitstring: exact;       //两种匹配项应该都可以
//     }
//     size = 1024;
//     //default_action = _drop;
// }

table totp{
    actions = {
        totp_implement;
        _drop;
    }
    key = {
        hdr.ipv6.dstAddr : exact;
        }
    size = 1024;
}

table send{
    actions = {
        send_ipv6;
        _drop;
    }
    key = {
        hdr.ipv6.dstAddr : exact;
    }
    size = 1024;
}

apply{
    
    // encap.apply();
    // decap.apply();
    // bift.apply();

    totp.apply();
    send.apply();
    //  if(!bift.apply().hit)
    //  {
    //      encap.apply();
    //      decap.apply();
    //  }
    //  if (hdr.bs.isValid() && hdr.bs2.isValid()) {
    //          hdr.bs2.bitstring = hdr.bs2.bitstring & ~hdr.bs.bitstring;    //对原报文中bs作处理，去除已经转发的标识
    //  }
    //  if (hdr.bs2.bitstring != 8w0 )
     
    //  {
    //      ig_dprsr_md.mirror_type = 1;
    //  }
    //  if(ig_dprsr_md.mirror_type ==1)
    //  {
    //       meta.mirror_session = 1;
    //  }
     
     
}

}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    // Mirror()mirror;
    
apply{

    // if(ig_dprsr_md.mirror_type == 1){
       
    //     mirror.emit<bitstring2_h>(meta.mirror_session,hdr.bs2);
    //     //mirror_session的id对应发往的端口号
    // }
    pkt.emit(hdr.ethernet);
    pkt.emit(hdr.ipv6);
    pkt.emit(hdr.ah);
    // pkt.emit(hdr.bier);
    // pkt.emit(hdr.bs);
    pkt.emit(hdr.icmpv6);
    pkt.emit(hdr.udp);


    
}

}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/
struct my_egress_headers_t {
    Ethernet ethernet;
    IPv6 ipv6;
    ICMPv6_h icmpv6;
    AH_h ah;
    // segment[10] segment_list;
    UDP_h udp;
    inthdr_h inthdr;
    
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    //bit<3> mirror_type;
    //bitstring_h bs2;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition select(eg_intr_md.egress_port)
        {
            default: parse_ethernet;
        }
    }
     state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType) {
            0x86dd:parse_ipv6;
            default:accept;
        }
    }
      state parse_ipv6{
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            17:parse_udp;
            58:parse_icmpv6;
            51:parse_ah;
            default:accept;
        }
    }

    state parse_ah{
       pkt.extract(hdr.ah);
       transition select(hdr.ah.nextHeader){
           17:parse_udp;
           default:accept;
       }
   }

    state parse_icmpv6{
       pkt.extract(hdr.icmpv6);
       transition accept;
   }
    
   state parse_udp{
       pkt.extract(hdr.udp);
       transition accept;
   }

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{

    action _drop(){
        eg_dprsr_md.drop_ctl = 1;
    }
    
    @name("do_int") 
    action do_int() {
        hdr.udp.udpLength = hdr.udp.udpLength + 16w22;
        hdr.udp.checksum = 16w0;
        hdr.ipv6.payloadLength=hdr.ipv6.payloadLength + 16w22;
        hdr.inthdr.setValid();
        // hdr.inthdr.device_no = meta.int_metadata.device_no;
        // hdr.inthdr.ingress_port = eg_oport_md.ingress_port;
        // hdr.inthdr.egress_port = eg_intr_md.egress_port;
        hdr.inthdr.ingress_global_timestamp = eg_prsr_md.global_tstamp;
        // hdr.inthdr.enq_timestamp = eg_intr_md.enq_timestamp;
        // hdr.inthdr.enq_qdepth = eg_intr_md.enq_qdepth;
        // hdr.inthdr.deq_timedelta = eg_intr_md.deq_timedelta;
        // hdr.inthdr.deq_qdepth = eg_intr_md.deq_qdepth;
    }

    @name("udp_int")
    table udp_int {
        actions = {
            do_int;
            _drop;
        }
        key = {}
        size = 1024;
        default_action = do_int();
    }

    apply {
        udp_int.apply();
        // if(mod_bier.apply().hit){}
        // else if(eg_intr_md.egress_port == RECIRCULATE_PORT)
        // {
        //     hdr.bs.bitstring = meta.bs2.bitstring;
        //     //eg_dprsr_md.drop_ctl = 0;
        // }
        // else{eg_dprsr_md.drop_ctl = 1;}
        // if((mod_bier.apply().hit)&&(eg_intr_md.egress_port == RECIRCULATE_PORT)){}
        // else{eg_dprsr_md.drop_ctl = 1;}
        //meta.bs2.bitstring.setInvalid();

    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.ah);
        pkt.emit(hdr.icmpv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.inthdr);
    }
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
