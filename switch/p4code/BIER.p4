/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<9> RECIRCULATE_PORT = 68;
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
    bit<16> ethernetType;
}


header IPv6{
    bit<4> version;
    bit<8> class;
    bit<20> flowlabel;
    bit<16> payloadlength;
    bit<8> nextheader;
    bit<8> hoplimit;
    IPv6Address srcAddr;
    IPv6Address dstAddr;
}
header BIER_h{
    bit<8> nextheader;      //4:IPv4  41:IPv6   143:Ethernet
    bit<8> extlength;
    bit<8> optiontype;
    bit<8> optionlength;
    bit<20> biftid;
    bit<3> tc;
    bit<1> s; //0
    bit<8> ttl;
    bit<4> nibble;
    bit<4> ver; //0
    bit<4> bsl; //log2(k)-5
    bit<20> entropy;
    bit<2> oam;
    bit<2> rsv;
    bit<6> dscp;
    bit<6> proto;       
    bit<16> bfirid;
    bit<96>bier_data;
}
header bitstring_h{
    bit<8> bitstring;
}

header bitstring2_h{
    bit<8> bitstring;
}

header UDP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplength;
    bit<16> checksum;
}
header ICMPv6_h{
   bit<8> type;
   bit<8> code;
   bit<16> checksum;
   bit<32> reserved;
   bit<128> target_address;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t{
    Ethernet ethernet;
    IPv6 ipv6;
    ICMPv6_h icmpv6;
    BIER_h bier;
    bitstring_h bs;
    bitstring2_h bs2;
    // segment[10] segment_list;
    UDP_h udp;
    
    
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<10> mirror_session;
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
        transition select(hdr.ipv6.nextheader){
            60:parse_bier;
            17:parse_udp;
            58:parse_icmpv6;
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
    state parse_bier{
        pkt.extract(hdr.bier);
        transition parse_bs;
    }
    state parse_bs{
        pkt.extract(hdr.bs);
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

action add_bier(bit<8> bitstring, bit<9> port){
    hdr.bier.setValid();
    hdr.bs.setValid();
    hdr.bs.bitstring = bitstring;
    hdr.ipv6.nextheader = 60;
    hdr.bier.extlength = 29;
    hdr.ipv6.payloadlength = hdr.ipv6.payloadlength +29;
    hdr.bier.optiontype = 0x11;
    hdr.bier.optionlength = 26;
    hdr.bier.nextheader = 59;       //不确定负载为什么类型
    ig_tm_md.ucast_egress_port = port;
    //ig_tm_md.ucast_egress_port = 192;

}

action del_bier(bit<9> port){
    hdr.ipv6.nextheader = hdr.bier.nextheader;
    hdr.bier.setInvalid();
    hdr.bs.setInvalid();
    ig_tm_md.ucast_egress_port = port;
    hdr.ipv6.payloadlength = hdr.ipv6.payloadlength -29;
    //ig_tm_md.ucast_egress_port = 192;  //recirculate

}

action clone_and_forward(bit<8> fbm,bit<9> port){
    
    hdr.bs2.setValid();
    hdr.bs2.bitstring = hdr.bs.bitstring;
    hdr.bs.bitstring = hdr.bs.bitstring & fbm;
    ig_tm_md.ucast_egress_port = port;
    ig_dprsr_md.mirror_type = 1;
    
}
action mcast(bit<16> mgroup){
    ig_tm_md.mcast_grp_a = mgroup;
}
action _drop(){
    ig_dprsr_md.drop_ctl = 1;
}
table encap{    //插入BIER头
    actions = {
        add_bier;
        _drop;
    }
    key = {
        hdr.ipv6.dstAddr:   exact;
    }
    size = 1024;
    //default_action = _drop;
}

table decap{    //去掉BIER头
    actions = {
        del_bier;
        
        _drop;
    }
    key = {
        hdr.ipv6.dstAddr:   exact;
        //hdr.bs.bitstring: exact;       //两种匹配项应该都可以
    }
    size = 1024;
    //default_action = _drop;
}

table bift{
    actions = {
        clone_and_forward;
        
        _drop;
    }
    key = {
        hdr.bs.bitstring:   ternary;
        
    }
    size = 1024;
    //default_action = _drop;
}

table mucast{
    actions = {
        mcast;
        _drop;
    }
    key = {
        hdr.ipv6.dstAddr:   exact;
    }
    size = 1024;
    //default_action = _drop;
}       //用作执行直接组播，待启用


apply{
    
    encap.apply();
    decap.apply();
    bift.apply();
    
    //  if(!bift.apply().hit)
    //  {
    //      encap.apply();
    //      decap.apply();
    //  }
    mucast.apply();
     if (hdr.bs.isValid() && hdr.bs2.isValid()) {
             hdr.bs2.bitstring = hdr.bs2.bitstring & ~hdr.bs.bitstring;    //对原报文中bs作处理，去除已经转发的标识
     }
    //  if (hdr.bs2.bitstring != 8w0 )
     
    //  {
    //      ig_dprsr_md.mirror_type = 1;
    //  }
     if(ig_dprsr_md.mirror_type ==1)
     {
          meta.mirror_session = 1;
     }
     
     
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
    Mirror()mirror;
    
apply{

    if(ig_dprsr_md.mirror_type == 1){
       
        mirror.emit<bitstring2_h>(meta.mirror_session,hdr.bs2);
        //mirror_session的id对应发往的端口号
    }
    pkt.emit(hdr.ethernet);
    pkt.emit(hdr.ipv6);
    pkt.emit(hdr.bier);
    pkt.emit(hdr.bs);
    pkt.emit(hdr.icmpv6);


    
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
    BIER_h bier;
    bitstring_h bs;
    bitstring2_h bs2;
    // segment[10] segment_list;
    UDP_h udp;
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
            68: parse_bs2;
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
        transition select(hdr.ipv6.nextheader){
            60:parse_bier;
            17:parse_udp;
            58:parse_icmpv6;
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
    state parse_bier{
        pkt.extract(hdr.bier);
        transition parse_bs;
    }
    state parse_bs{
        pkt.extract(hdr.bs);
        transition accept;
    }
    state parse_bs2{
        pkt.extract(hdr.bs2);
        transition parse_ethernet;
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

    action mod_bs(IPv6Address dstaddr)
    {
        hdr.ipv6.dstAddr = dstaddr;//是否需要修改地址
        //hdr.bs.bitstring = bitstring; 
    }

    action _drop(){
    eg_dprsr_md.drop_ctl = 1;
    }
    table mod_bier{
        actions = {
            mod_bs;
            _drop;
        }
        key = {
            eg_intr_md.egress_port:   exact;
        }
        size = 1024;
        //default_action = _drop;
    }
    apply {
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
        if(hdr.bs2.isValid()){
            hdr.bs.bitstring = hdr.bs2.bitstring;
            hdr.bs2.setInvalid();
        }
        mod_bier.apply();

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
        pkt.emit(hdr.bier);
        pkt.emit(hdr.bs);
        pkt.emit(hdr.icmpv6);
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
