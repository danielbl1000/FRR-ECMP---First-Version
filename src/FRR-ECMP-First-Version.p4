#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_FOWARDING_TAG = 0x010;


typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> dst_id_t;
typedef bit<16> src_id_t;
typedef bit<16> protocol_type_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}


//Disable
//header fowarding_tag_t {
//    dst_id_t dst_id;
//    protocol_type_t protocol_type;
//}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> ecmp_hash;
    bit<32> ecmp_group_id;
    bit<9> count;
    bit<1> link_state;
    bit<1> link_local;
    bit<1> link_network;
    bit<32> hash1;
    bit<32> ecmp_path_selector;
    bit<48> dst_id;
    bit<32> r_begin_path;
    bit<32> r_num_paths;
    bit<32> id_move;    
    bit<9> egress_spec_port;
    bit<32> port_counter;
    bit<32> dst_id_ecmp_path_selector;
    bit<32> dst_id_port_down;
    bit<32> dst_id_r_num_paths;
}

//Disable
/*
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    fowarding_tag_t fowarding_tag;
}
*/


struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}




/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        transition parse_ethernet;

    }


//Disable
/*
state parse_ethernet {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_FOWARDING_TAG: parse_fowarding_tag; 
            default: accept;
        }
    }

  state parse_fowarding_tag {
          packet.extract(hdr.fowarding_tag);
// No parser o meta.dst recebe o DST_ID do next hop, usado no fowarding_tag para encaminhar pacotes;
          meta.dst_id = hdr.fowarding_tag.dst_id;
          transition select(hdr.fowarding_tag.protocol_type) {
          TYPE_IPV4: parse_ipv4;
          default: accept; 
         }
     }

*/



state parse_ethernet {

        packet.extract(hdr.ethernet);
        meta.dst_id = hdr.ethernet.dstAddr;
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
  //          meta.dst_id = hdr.ethernet.dstAddr;
            default: accept;
        }
    }


state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

   state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

       
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
//Disable
   //     packet.emit(hdr.fowarding_tag);
        packet.emit(hdr.ipv4);

        //Only emited if valid
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { 

    //  update_checksum
          verify_checksum_with_payload(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

     }
}
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

 action drop_act() {
       standard_metadata.egress_spec = 511;
     }

 action nop() {

    }

 action compute_hash() {
         hash(meta.hash1, HashAlgorithm.crc32,
              (bit<16>) 0,
              {hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.ipv4.protocol,
               hdr.tcp.srcPort,
               hdr.tcp.dstPort},
               (bit<32>) 65536); 

           }  
            
//Disable
/*
 action set_nhop_local(macAddr_t dstAddr, egressSpec_t port) { 
     hdr.ethernet.etherType = 0x800; 
     hdr.ethernet.dstAddr = dstAddr;
     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
     hdr.fowarding_tag.setInvalid(); 
     standard_metadata.egress_spec = port;  
     meta.dst_id = 0; 
   }
*/



 action set_nhop_local(macAddr_t dstAddr, egressSpec_t port) {
     hdr.ethernet.etherType = 0x800;
     hdr.ethernet.dstAddr = dstAddr;
     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
//     hdr.fowarding_tag.setInvalid();
     standard_metadata.egress_spec = port;
     meta.dst_id = 0;
   }


 action set_nhop_network(dst_id_t dst_id) {
     meta.dst_id = dst_id;
   }   


table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop_local;
            set_nhop_network;
            drop_act;
        }
        size = 1024;
     
    }



// HASH1 Tuple 5 TEST

 register<bit<16>>(100) ecmp_hash_register_begin_path;
 register<bit<32>>(100) ecmp_hash_register_num_path;

 action set_ecmp_hash_register() {
         bit<16> r_begin_path;
         bit<32> r_num_paths;
         bit<16> total_begin_path;
         bit<32> total_num_paths;
         ecmp_hash_register_begin_path.read(r_begin_path,(bit<32>)meta.dst_id);
         ecmp_hash_register_num_path.read(r_num_paths, (bit<32>)meta.dst_id);
         meta.r_num_paths = r_num_paths;
         hash(meta.ecmp_path_selector, HashAlgorithm.crc32,
                 r_begin_path,     
                 {hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr,
                 hdr.ipv4.protocol,
                 hdr.tcp.srcPort,
                 hdr.tcp.dstPort},
                 r_num_paths);  
       }       


table ecmp_hash {
        key = {
                       
            meta.dst_id: exact;
        }
        actions = {
            drop_act;
            set_ecmp_hash_register;
         }
        size = 1024;
    }

 register<bit<9>>(100) fowarding_tag_ecmp_register_path;        
 register<bit<32>>(512) fowarding_tag_ecmp_register_path_down;   

// Disable
/*
 action set_fowarding_tag_ecmp_register() {
         bit<9> port;               
         hdr.ethernet.etherType = 0x010;
         hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
         hdr.fowarding_tag.setValid();
         hdr.fowarding_tag.dst_id =  meta.dst_id;
         hdr.fowarding_tag.protocol_type = 0x800;
         meta.dst_id_ecmp_path_selector = (bit<32>)meta.dst_id * 10 + meta.ecmp_path_selector;  
         fowarding_tag_ecmp_register_path.read(port, meta.dst_id_ecmp_path_selector);
         standard_metadata.egress_spec = port;
       } 
*/



 action set_fowarding_tag_ecmp_register() {
         bit<9> port;
         hdr.ethernet.etherType = 0x010;
         hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
  //       hdr.fowarding_tag.setValid();
  //       hdr.fowarding_tag.dst_id =  meta.dst_id;
         hdr.ethernet.dstAddr = meta.dst_id;  
  //       hdr.fowarding_tag.protocol_type = 0x800;
         hdr.ethernet.etherType = 0x800; 
         meta.dst_id_ecmp_path_selector = (bit<32>)meta.dst_id * 10 + meta.ecmp_path_selector;
         fowarding_tag_ecmp_register_path.read(port, meta.dst_id_ecmp_path_selector);
         standard_metadata.egress_spec = port;
       }



table  fowarding_tag {
        actions = {
            set_fowarding_tag_ecmp_register;
            drop_act;
            nop; 
       }          
         key = {
             meta.dst_id : exact;  
             meta.ecmp_path_selector : exact;
  
         }
         size = 512;
         default_action = nop;
    } 


 register<bit<1>>(100) port_state;

  action set_link_state(bit<32> port, bit<1> link_state) {
        meta.link_state = link_state;
        port_state.write(port, link_state);
      }
   
    table egress_port_link_state {
         actions = {
            set_link_state;
            drop_act;
            nop; 
         }
         key = {
             standard_metadata.egress_spec : exact;
         }
         size = 512;
         default_action = drop_act;
    }



// Registro de contador quando ocorre falha e registro de loop 
 register<bit<32>>(100) count_port_register;
 register<bit<1>>(1) bit_loop;     

//Registro de controle de caminhos/portas down e contador
 register<bit<32>>(100) port_register_down; 
 register<bit<32>>(10) fowarding_tag_register_num_path_down;
 register<bit<32>>(10) fowarding_tag_register_num_path_count;    

 
apply {

       ipv4_lpm.apply();   
       ecmp_hash.apply();
       fowarding_tag.apply();
       egress_port_link_state.apply();


       bit<1> loop_ok;
       bit<1> loop_check;
       bit_loop.read(loop_ok,0);
       loop_check = loop_ok;

// SE A PORTA DE DESTINO ESTA DOWN (bit 1) E DST ID VALIDO (!=0) OU ESTA EM LOOP REORDENANDO OS REGISTROS 
 
       if (meta.link_state == 1 && meta.dst_id != 0 || loop_check == 1)  { 
// read__ecmp_hash_num_path__fw_tag_ecmp_reg_path__meta_dst_port_down();
// rd ecmp_hash_register_num_path[2]= 6
// rd ecmp_hash_register_begin_path[2]= 1
// rd fowarding_tag_ecmp_register_path[21]= 1
// meta.dst_id_port_down = 2 * 10 + 1 (port) => [21]
              

      
                     bit<32> r_num_paths;
                     bit<16> r_begin_path;
                     ecmp_hash_register_num_path.read(r_num_paths, (bit<32>)meta.dst_id);
                     ecmp_hash_register_begin_path.read(r_begin_path,(bit<32>)meta.dst_id);
                     meta.r_num_paths = r_num_paths;                     
                     meta.r_begin_path = (bit<32>)r_begin_path;  
                   
                     bit<9> port_move1;
                     bit<9> port_move2;
                     bit<32> id_move ;
                     bit<32> count_aux;             
                     fowarding_tag_ecmp_register_path.read(port_move1, meta.dst_id_ecmp_path_selector);
                     meta.dst_id_port_down = (bit<32>)meta.dst_id * 10 + (bit<32>)port_move1;


                     if (loop_check == 0 && port_move1 != 0){
// write__fw_tag_ecmp_reg_path_down_bit_1__port_reg_down_add_port__fw_tag_reg_num_path_down_add_1();
// wr fowarding_tag_ecmp_register_path_down[21]= 1
// wr port_register_down[21]= 3
// wr fowarding_tag_register_num_path_down[2]= 0 + 1

                     fowarding_tag_ecmp_register_path_down.write((bit<32>)meta.dst_id_port_down, 1);            
                     bit<32> aux1_return;                     
                     fowarding_tag_register_num_path_down.read(aux1_return, (bit<32>)meta.dst_id);
                     port_register_down.write((bit<32>) meta.dst_id * 10 + aux1_return + 1 ,(bit<32>)port_move1);  
                     fowarding_tag_register_num_path_down.write((bit<32>)meta.dst_id, aux1_return + 1);


                     }    

// read-count_port_reg-total_num_paths() 
// Carrega contador de registro count_port_register[2]=X, depois permite verifica as posicoes fowarding_tag_ecmp_register_path[2X]= Port
// no IF ( meta.id_move < meta.dst_id_r_num_paths)  
// rd count_port_register (contador)
// meta.dst_id_ecmp_path_selector = (bit<32>)meta.dst_id * 10 + meta.ecmp_path_selector;
// id_move = contador + 2 * 10 + 1
// dst_id_r_num_paths = 2 * 10 + total de paths
// Depois entra na condicao IF 21 < 26 => THEN ou IF 26 == 26   
                                      
                     count_port_register.read(count_aux,(bit<32>)meta.dst_id);  
                     meta.id_move = count_aux + meta.dst_id_ecmp_path_selector;
                     meta.dst_id_r_num_paths = (bit<32>)meta.dst_id * 10 + meta.r_num_paths;                    


// IF [21] < [26] Then -> Copia a porta do proximo registro para o registro atual em fowarding_tag_ecmp_register_path
 
                     if ( meta.id_move < meta.dst_id_r_num_paths) {

// write-cp_next_reg_to_current_fw_tag_ecmp_reg-count_1-resubmit()
// Copia de fowarding_tag_ecmp_register_path[23]= 3
// Para fowarding_tag_ecmp_register_path[22]= 3
// depois incrementa count_port_register[2]= count + 1
// setar o bit_loop[0] = 1
// por fim, resubmit

                             fowarding_tag_ecmp_register_path.read(port_move2, meta.id_move + 1);  
                             fowarding_tag_ecmp_register_path.write(meta.id_move, port_move2);                    
                             fowarding_tag_ecmp_register_path.write(meta.id_move + 1, 0);
                             count_port_register.write((bit<32>)meta.dst_id, count_aux + 1);
     
                             bit_loop.write(0,1);
                             resubmit(meta);
                      }   
                   
// IF [26] == [26] Then -> Inclui zero, reduz o numero de paths, desabilita loop e reenvia o pacote, novo ecmp hash

                     if ( meta.id_move ==  meta.dst_id_r_num_paths ) {

// Zera o contador registro count_port_register[2]=0
// Decrementa -1 no registro ecmp_hash_register_num_path[2]= 6 - 1
// Inclui a porta 0 na ultima pisicao no registro fowarding_tag_ecmp_register_path[26]=0  
// bit_loop[0] = 0, desabilta o loop
// por fim, resumit
// O pacote sera enviado para o inicio do pipeline e calculado um novo ecmp hash para o totla de 5 paths

           
                              count_port_register.write((bit<32>)meta.dst_id, 0);
                              ecmp_hash_register_num_path.write((bit<32>)meta.dst_id, r_num_paths - 1);       
                              fowarding_tag_ecmp_register_path.write(meta.id_move, 0);
                              bit_loop.write(0,0);
                              resubmit(meta);
                          
                     }
 
                    // 01 FIX BUG BASE = 0 QUANDO MAX=0, POIS ECMP_SELECTOR ATUA COMO 1
                    // QUANDO Num paths < Begin paths, Faz Begin path = 0
// TEST - DISABLE
//                     if (meta.r_begin_path > meta.dst_id_r_num_paths){ 
  //                       ecmp_hash_register_begin_path.write((bit<32>)meta.dst_id,(bit<16>)meta.r_begin_path - 1);
 //                     }   


       } 
        
         
// SE NAO ESTA REORDENANDO OS REGISTROS EM CASO DE FALHA, ENTAO DEVE VERIFICAR NO REGISTRO O RETORNO DOS CAMINHOS 
// Link = UP (bit 0) e DST_ID VALIDO (!=0)
        else if (meta.link_state == 0 && meta.dst_id != 0) {

// O index inicial do registros fowarding_tag_registe_X devem terminar com 1 (ex 21,31,101,etc) 
                               
                             if (meta.dst_id_r_num_paths == 1 && meta.r_begin_path == 0 ){
                                  ecmp_hash_register_begin_path.write((bit<32>)meta.dst_id, (bit<16>)meta.r_begin_path + 1);
                             }  
// read-fw_tag_reg_num_path_count-fw_tag_reg_num_path_down-port_reg_down-fw_tag_ecmp_res_down-port_state;
// Carrega os principais registros utilizados quando recebe uma porta que um caminho falha
// rd fowarding_tag_register_num_path_count[2]= X, contador de posicao do port_register_down[2X]= port
// rd fowarding_tag_register_num_path_down[2]= TOTAL de portas down, sera recebido por total_down_port e usado no IF
// rd port_register_down[22]= 5, verifica a porta na posicao 2 (dst_id) * 10 + aux2_return (contador de fowarding_tag_register_num_path_count)
// rd fowarding_tag_ecmp_register_path_down[22]= 1, o registro armazena os caminhos down, bit 1 indica down.
// rd port_state[3]= 1, registro indicando se a porta 3 esta down/up (bit 1 e down)

                              bit<32> bit_port_return_fw;
                              bit<1>  bit_port_return;
                              bit<32> port_return;                      
                              bit<32> total_down_port;
                              bit<32> total_down_port_sub_1;
                              bit<32> aux2_return;
                              bit<32> cp_next_port;
                              fowarding_tag_register_num_path_count.read(aux2_return, (bit<32>)meta.dst_id);                            
                              fowarding_tag_register_num_path_down.read(total_down_port, (bit<32>)meta.dst_id);
                              port_register_down.read(port_return,(bit<32>) meta.dst_id * 10 + aux2_return);
                              fowarding_tag_ecmp_register_path_down.read(bit_port_return_fw, (bit<32>) meta.dst_id * 10 + port_return); 
                              port_state.read(bit_port_return, port_return);
// Condicao para verificar enquanto o contador fowarding_tag_register_num_path_count < fowarding_tag_register_num_path_down
  
                               if (aux2_return < total_down_port){ 
                               

// Entrando na condicao que verifica quando ocorre saida de pacotes para um determinado DST, entao
// Se a porta esta UP (bit 0) e caminho esta down, deve retornar o caminho pois a porta esta UP  
//IF bit_port_return_fw (fowarding_tag_ecmp_register_path_down[22]=1) e  bit_port_return (port_state.read[3] == 1) Then   

                                       if (bit_port_return_fw == 1 && bit_port_return == 0 ) {                                 
// read-ecmp_hash_register_num_path[2]= 1, realiza a leitura do total de paths, pois sera incrementado + 1 nos registros
// r_num_paths_return_write, recebe 2 * 10 + 1
// write-fw_tag_ecmp_res_path-ecmp_hash_res_num_path
// fowarding_tag_ecmp_register_path, na ultima posicao do registro, salva a porta que acabou de retornar
// ecmp_hash_register_num_path, incrementa + 1 no total de caminhos UP no registro
// fowarding_tag_ecmp_register_path_down[21]= 0, inclui ZERO (0) na posicao da porta que retornou, desabilitando o down
// port_register_down[22]= 5, copia a porta da proxima posicao para posicao atual 
// port_register_down[21]= 5
// port_register_down[22]= 0, inclui ZERO (0) na proxima posicao
                                    
                                            bit<32> r_num_paths_return;
                                            bit<32> r_num_paths_return_write;

                                            ecmp_hash_register_num_path.read(r_num_paths_return, (bit<32>)meta.dst_id);
                                            r_num_paths_return_write = (bit<32>)meta.dst_id * 10 + r_num_paths_return;
                                            fowarding_tag_ecmp_register_path.write(r_num_paths_return_write + 1, (bit<9>)port_return);
                                            ecmp_hash_register_num_path.write((bit<32>)meta.dst_id, r_num_paths_return + 1);
                                            fowarding_tag_ecmp_register_path_down.write((bit<32>) meta.dst_id * 10 + (bit<32>)port_return, 0);
                                            port_register_down.read(cp_next_port, (bit<32>) meta.dst_id * 10 + aux2_return + 1); 
                                            port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return,cp_next_port);    
                                            port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return + 1, 0);                                                         
                                            // CP AUX2 e AUX2+1 =0

 
                                        }

                                          
                                         bit<32> port_return_previous_1;
                                         port_register_down.read(port_return, (bit<32>) meta.dst_id * 10 + aux2_return);
                                         port_register_down.read(port_return_previous_1 ,(bit<32>) meta.dst_id * 10 + aux2_return - 1);
                                          //movimenta o zero


// IF a porta do index atual no registro de port_register_down [X]!= 0 (porta valida) E  posicao anterior = 0 E 
// IF index anterior NAO e posicao [20], terminado com ZERO, pois nesta posicao sempre sera bit 0,
// THEN COPIA a PORTA VALIDA PARA O REGISTRO ANTERIOR, depois inclui ZERO na atual posicao.

                                          if (port_return != 0 && port_return_previous_1 == 0 && (bit<32>) meta.dst_id * 10 + aux2_return - 1 >  (bit<32>) meta.dst_id * 10 ) {

                                             // Verifica se o registro pode CP para anteiror que (se for 0), entre [1]..[total-1]
                                             //   AUX2[i]!=0,  
                                             //   AUX2[i-1]=0
                                             //   AUX2[i]> [0] THEN CP AUX2[i-1]= AUX2[i]   
                                             
                                             port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return - 1, port_return);
                                             port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return,0);

                                           }   


// INCREMENTA + 1 no CONTADOR fowarding_tag_register_num_path_count[2]= 3 + 1
                                         // AUX2 = AUX2 + 1
                                         fowarding_tag_register_num_path_count.write((bit<32>)meta.dst_id, aux2_return + 1); 

                                         
// Condicao para verificar quando o contador fowarding_tag_register_num_path_count = fowarding_tag_register_num_path_down

                               } else if (aux2_return == total_down_port) {

// De forma semelhante na condicao aux2_return < total_down_port, se a porta esta UP em port_state[1]= 0, entao deve retornar para
// os registros de caminho ativo e excluir a porta dos registro de caminho inativo                                                                                  
                                        port_register_down.read(port_return,(bit<32>) meta.dst_id * 10 + aux2_return);  
                                       if (bit_port_return_fw == 1 && bit_port_return == 0 ) {
                                            bit<32> r_num_paths_return;
                                            bit<32> r_num_paths_return_write;
                                            ecmp_hash_register_num_path.read(r_num_paths_return, (bit<32>)meta.dst_id);
                                            r_num_paths_return_write = (bit<32>)meta.dst_id * 10 + r_num_paths_return;
                                            fowarding_tag_ecmp_register_path.write(r_num_paths_return_write + 1, (bit<9>)port_return);
                                            ecmp_hash_register_num_path.write((bit<32>)meta.dst_id, r_num_paths_return + 1);                                                        fowarding_tag_ecmp_register_path_down.write((bit<32>) meta.dst_id * 10 + (bit<32>)port_return, 0);                                     
                                            port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return,0);   
                                                                                      
                                         }  

                                         
                                         bit<32> port_return_previous_1_test2;
                                         port_register_down.read(port_return,(bit<32>) meta.dst_id * 10 + aux2_return);      
                                         port_register_down.read(port_return_previous_1_test2 ,(bit<32>) meta.dst_id * 10 + aux2_return - 1); 

                                            // OK QUANDO RETORNA A PORTA DO ULTIMA POSICAO, DECREMENTA
                                         if (port_return == 0 && total_down_port > 0) {

                                            fowarding_tag_register_num_path_down.read(total_down_port, (bit<32>)meta.dst_id); 
                                            total_down_port_sub_1 = total_down_port - 1;
                                            fowarding_tag_register_num_path_down.write((bit<32>)meta.dst_id, total_down_port_sub_1); 

                                           // IF RESPONSAVEL POR MOVER A PORTA PARA POSICAO ANTERIOR, COLOCAR ZERO NA A
                                           // ATUAL POSICAO E DECREMENTAR O TOTAL DE PORTAS DOWN OK
                                         } else if (port_return != 0 && port_return_previous_1_test2 == 0 && (bit<32>) meta.dst_id * 10 + aux2_return - 1 > (bit<32>) meta.dst_id * 10 ) {

// Se chegar no ultimo registro, então se for != N e uma posicao anteriro == 0 tb não seja posicao 0
// Copia N para a posicao anterior
                                             port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return - 1,port_return);
                                             port_register_down.write((bit<32>) meta.dst_id * 10 + aux2_return,0); 
                                            
                                             fowarding_tag_register_num_path_down.read(total_down_port, (bit<32>)meta.dst_id);
                                             total_down_port_sub_1 = total_down_port - 1;
                                             fowarding_tag_register_num_path_down.write((bit<32>)meta.dst_id, total_down_port_sub_1); 
                                           
                                         }   
                                        
                                         fowarding_tag_register_num_path_count.write((bit<32>)meta.dst_id, 1);
 

                               // BUG AUX2 > AUX1, ocorre quando movimenta muita as portas com trafego
                             } else if (aux2_return > total_down_port) {
                                 
                                      fowarding_tag_register_num_path_count.write((bit<32>)meta.dst_id, aux2_return - 1);   


                             }

              } 

// IF porta local esta down, entao descarte o pacote
      else if (meta.link_state == 1 && meta.dst_id == 0) {
                   drop_act();
               } 


       } 
 

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {

    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
