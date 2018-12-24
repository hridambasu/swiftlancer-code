pragma solidity ^0.4.25;
pragma experimental ABIEncoderV2;

import "./SimplifiedBigNumber.sol";


contract SwiftLancerFinal{
    
    event debug(bytes32 a);
    
    event debug1(bytes32 b);
    
    event FillGold(string a);
    
    event OpenGold(string b);
    
    event PlainTextProof(string a);
    
    // answers of workers
    struct answers {
        bytes32[106] ciphers;
        uint counter;
    }
    
    enum Protocol_State{Task_Publish, Collecting_Answers, Collected}
    Protocol_State state;
    using BigNumber for *;
    address owner;
    uint public current_worker_num;
    uint public question_num;
    uint public num_workers;
    uint public gold_num;
    uint public num_questions;
    uint public gold_count; 
    uint[6] actual_gold_indices;
    uint[6] actual_gold_solutions;
    
    
    bytes g_val = hex"3d18c64b862beb04ecd05ba788a5aa57877bedaf24380d7d73335927c07461b7d435ed96b597f79b479b0014e8552da81b52f9dbb23b1599f84aa6cd49f6a93cae96708bde27a57f5193429711ac74f2befb85adae6b5365855ea417613813dccabbe535d04f043f3bb6a9b3b3574e58f82d30e9019ea6bc2e09f3d27123e51b90c13f55f51067563ba0589947e94893eab7676c70bfc6d587f0a20363bcb2e06b0b72faff29cc6ab0a52116017a8a29df7c82d77e8a21de50bdc706c9b6c9e1ad98aa40b1c0970d2278604f8d8fc67081d860a677ace7d8f2baa14d51887e2d5b85bdffc2e820c24a89674fa07bae629dae46810a477e3b1244cba88b59010d";
    bytes h_val = hex"68f99baf7006ba11870b10a34945bf3901886c1e5f94caf9097d1efb77ba64c40883ec380ac1167ab15a9acaf64d994d74c0a7a0066bd34717c6aa71eb1a515da37cc6ebaebf23811e8ad437927de44b7662946b9f112d19152de685341d20afdf89c37461e0ceeb81cdf493753c7d8ce0e3c327d48b2fddf3966ab414d57a33e4d6f9ac88ba574953bd85a21942da63274f92a78ca3e94165ac696b209be0e4fbe9918b7b568a4dce48b176e3faef3547f25c30188ca38f1ca332463f9a408606d05643383e9db516a3d5c50dab465a17d17120f2fa26b0460b42fe9288e6a8453ccc10eb5d7cc7fb00763533d502900df8ab7413e29139c85fefb1509cd9f9";
    bytes p_val = hex"d295fa41d34eeee303f972b94c20941295c6d5684c78f04304f50a146f2856b3042c56dce82d1c126e03b623b87aae58e073073bdc540f6668f584220bd6ed49ce0e9c3145e75fe6e677405b55ed52487337f35115912daa1d6806d0544df97ecea65e9a968897aca0a473c0abe1986326596bfe6fa1422ec445908821dca46e32aba8038a248b0d8bc3f4a40bc9cc80299c4ae258a4d785d3f20831435f446d49004425b787e1214c14769f60625053809602881a7eac6bcd064b662e1f9ed937164387a721ad382ea0abdb8d184953653e9fd1d5560e7f9e8cb4b7e05091767e76a4be0d9ae268334da70a1a2ec0d49c6cfe8257222554dffacf884d568063";
    
    
    uint g_bitlen = 2046;
    uint h_bitlen = 2047;
    uint p_bitlen = 2048;
    
    
    BigNumber.instance g=BigNumber.instance(g_val,g_bitlen);
    BigNumber.instance h=BigNumber.instance(h_val,h_bitlen);
    BigNumber.instance p=BigNumber.instance(p_val,p_bitlen);
    
    event Ciphertexts(
        bytes c1,
        bytes c2
    );
    
    event Answers_Test(string b);
    
    struct GoldenStandard{
        bytes32[6] index_val;
        bytes32[6] sol_val;
        uint ctr;
    }
    
    GoldenStandard public gs;
    
    mapping(address => answers) public answers_map;
    
    bytes32[4][106] ciphers;
    
    address[] public workers_accts;
    
    constructor () public{
        state = Protocol_State.Collecting_Answers;
        owner = msg.sender;
        current_worker_num = 1;
        question_num = 1;
        num_workers = 4;
        gold_num = 1;
        num_questions = 106;
        gold_count = 6;
    }
    
    //filling the golden standard commitments with indices and their respective solutions
    function fill_golden(bytes32 i_val, bytes32 s_val){
        gs.index_val[gs.ctr] = i_val;
        gs.sol_val[gs.ctr] = s_val;
        gs.ctr += 1;
        emit FillGold("Gold array filled!");
        emit debug(i_val);
    }
    
    // opening the commitments and checking if it matches with the committed values
    function opening_phase(uint[] indices, uint[] sols, uint r_val) returns (bool){
        for(uint i=0;i<gold_count;i++){
            bytes32 lhs1 = sha3(sha3(indices[i]), sha3(r_val));
            bytes32 lhs2 = sha3(sha3(sols[i]), sha3(r_val));
            
            if((lhs1 == gs.index_val[i]) && (lhs2 == gs.sol_val[i])){
                actual_gold_indices[i] =  indices[i];
                actual_gold_solutions[i] = sols[i];
                emit OpenGold("Commitment to index and sol correct!");
                continue;
            }
            else{
                emit OpenGold("Commitment to index and sol false!");
                return false;
            }
        }
        return true;
    }
    
    // reading ciphertext digest given worker address and question number
    function read_cipher_digest (address addr, uint question_index) returns (bytes32) {
        return answers_map[addr].ciphers[question_index];
    }
    
    // different plaintext proof for proving that worker did not provide correct solution of golden standard questions
    function different_plaintext_proof(bytes c1_val, uint c1_bitlen, bytes c2_val, uint c2_bitlen, uint q_index, address worker_index, bytes a_val, uint a_bitlen, bytes z_val, uint z_bitlen, uint hash_length) returns (bool){
        
        BigNumber.instance memory lhs;
        BigNumber.instance memory rhs;
        for(uint i=0; i<gold_count; i++){
            if(q_index == actual_gold_indices[i]){
                if(answers_map[worker_index].ciphers[q_index] == sha3(c1_val, c2_val)){
                    (lhs.val, lhs.bitlen) = different_plaintext_proof_lhs(c1_val, c1_bitlen, z_val, z_bitlen, a_val, hash_length, 1 - actual_gold_solutions[i]);
                    (rhs.val, rhs.bitlen) = different_plaintext_proof_rhs(c2_val, c2_bitlen, a_val, a_bitlen, hash_length);
                    if(BigNumber.cmp(lhs, rhs, true) == 0){
                        emit PlainTextProof("Different Plaintext Verified!");
                        return true;
                    }
                    else{
                        emit PlainTextProof("Malicious Plaintext Proof!");
                        return false;
                    }
                }
                else{
                    emit PlainTextProof("Hashes of Ciphertexts don't match");
                    return false;
                }
            }
        }
        return false;
    }
    
    // computing left hand side of the different plaintext proof
    function different_plaintext_proof_lhs(bytes c1_val, uint c1_bitlen, bytes z_val, uint z_bitlen, bytes a_val, uint hash_length, uint solexp) returns (bytes, uint){
        BigNumber.instance memory c;
        
        c.val = toBytes(sha3(a_val, g_val, h_val));
        c.bitlen = hash_length;
        
        BigNumber.instance memory c1;
        
        c1.val = c1_val;
        c1.bitlen = c1_bitlen;
        
        BigNumber.instance memory z;
        
        z.val = z_val;
        z.bitlen = z_bitlen;
        
        BigNumber.instance memory lhs;
        
        if(solexp == 1){
            lhs = (c1.prepare_modexp(z,p)).modmul(g.prepare_modexp(c,p),p);
        }
        else{
            lhs = c1.prepare_modexp(z,p);
        }
        return (lhs.val, lhs.bitlen);
    }
    
    // computing right hand side of the different plaintext proof
    function different_plaintext_proof_rhs(bytes c2_val, uint c2_bitlen, bytes a_val, uint a_bitlen, uint hash_length) returns (bytes, uint){
        
        BigNumber.instance memory c;
        
        c.val = toBytes(sha3(a_val, g_val, h_val));
        c.bitlen = hash_length;
        
        BigNumber.instance memory a;
        
        a.val = a_val;
        a.bitlen = a_bitlen;
        
        BigNumber.instance memory c2;
        
        c2.val = c2_val;
        c2.bitlen = c2_bitlen;
        
        BigNumber.instance memory rhs = a.modmul(c2.prepare_modexp(c,p),p);
        
        return (rhs.val, rhs.bitlen);
    }
    
    // workers submitting answers to the contract
    function submit_answers(uint i, bytes c_1, bytes c_2) {
        address worker = msg.sender;
        bytes32 hash_val = sha3(c_1, c_2);
        emit Ciphertexts(c_1, c_2);
        if (i > 0) {
            answers_map[worker].ciphers[i] = hash_val;
            answers_map[worker].counter += 1;
            emit debug(answers_map[worker].ciphers[i]);
        } 
        else {
            answers hisAnswers;
            hisAnswers.ciphers[0] = hash_val;
            hisAnswers.counter = 1;
            answers_map[worker] = hisAnswers;
            emit debug(answers_map[worker].ciphers[0]);
        }
    }
    
    function toBytes(uint256 x) returns (bytes b) {
        b = new bytes(32);
        assembly { mstore(add(b, 32), x) }
    }
    
    function toBytes(bytes32 _data) public pure returns (bytes) {
        return abi.encodePacked(_data);
    }
}


        
        
        
        
        