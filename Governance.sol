// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;
interface IGovernance{
    
}
contract Governance{
    address relayer = 0xb765B7A732e6fd80E3a6cC4b2FfD489eAc0d2501;
    address public contractAddress;
    string public governanceName;
    uint public totalEndExamination;
    address public owner;
    string public batch;
    mapping(address=>bool) public student;
    mapping(address=>bool) public grader;
    mapping(address=>bool) public hod;
    mapping(address=>bool) public mentors;
    enum ProposalStatus{
        pending,
        approved,
        rejected
    }
ProposalStatus public proposalStatus;
struct Proposal{
        string ipfsCID;
        ProposalStatus _proposalStatus;
        uint numOfUpVote;
        uint numOfDownVote;
}

Proposal[] public proposal;
uint currentNumOfProposal = 0;
uint public graderNonceCount = 0;
mapping(uint=>bool) closeProposalNonce;
struct Certificate{
    string ipfsCID;
    bool status;
}
mapping(address=>mapping(uint=>Certificate)) public semCertIssuance;
mapping(address=>Certificate) public degreeCert;
mapping(address=>uint) public currentSemester;
mapping(string=>bool) public isUsedReceipt;
uint internal immutable CHAIN_ID;
bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;
uint public nonce;
mapping (uint=>address) public graderNonce;
mapping (uint=>address) public studentNonce;
mapping (uint=>address) public mentorNonce;
mapping (uint=>address) public hodNonce;
mapping(uint=>bool) isUniqueIdUsed;
constructor(string memory _governanceName,uint _totalEndExamination, address _owner,string memory _batch){
contractAddress = address(this);
governanceName = _governanceName;
totalEndExamination =_totalEndExamination;
owner = _owner;
batch = _batch;
CHAIN_ID = block.chainid;
INITIAL_DOMAIN_SEPARATOR = hashDomain(_governanceName,"1",block.chainid,address(this));
}
modifier Elig(address add,uint uniqueId){
require(student[add] != true,"YAS");
require(grader[add] != true,"YAG");
require(mentors[add] != true,"YAM");
require(hod[add] != true,"YAH");
require(owner != add,"OCM");
require(isUniqueIdUsed[uniqueId] != true,"IAU");
    _;
}

// Grader Hashing and Becoming Grader
function hash(address add,string memory _secretKey_1, string memory _secretKey_2,string memory role,uint256 uniqueId) public  pure returns(bytes32){
return (keccak256(abi.encode(
keccak256(bytes("Enroll(address account,string _secretKey_1,string _secretKey_2,string role,uint256 uniqueId)")),
add,
keccak256(bytes(_secretKey_1)),
keccak256(bytes(_secretKey_2)),
keccak256(bytes(role)),
uniqueId
)));
}

function becomeGrader(address graderAddress,string memory _secretKey_1, string memory _secretKey_2, string memory role,uint256 uniqueId,uint8 v, bytes32 r, bytes32 s) Elig(graderAddress,uniqueId)  external{
require(keccak256(bytes(role)) == keccak256(bytes("grader")),"GSOA");
bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hash(graderAddress,_secretKey_1, _secretKey_2,role,uniqueId)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == owner,"INVALID_SIGNER");
grader[graderAddress] = true;
isUniqueIdUsed[uniqueId] = true;
graderNonce[nonce] = graderAddress;
nonce++;
}

function becomeHod(address hodAddress,string memory _secretKey_1, string memory _secretKey_2, string memory role,uint256 uniqueId,uint8 v, bytes32 r, bytes32 s) Elig(hodAddress,uniqueId)  external{
require(keccak256(bytes(role)) == keccak256(bytes("hod")),"HSOA");
bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hash(hodAddress,_secretKey_1, _secretKey_2,role,uniqueId)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == owner,"INVALID_SIGNER");
hod[hodAddress] = true;
isUniqueIdUsed[uniqueId] = true;
hodNonce[nonce] = hodAddress;
nonce++;
}
 
//  student hashing and become student
function becomeStudent(address studentAddress,address signer,string memory _secretKey_1, string memory _secretKey_2, string memory role,uint256 uniqueId,uint8 v, bytes32 r, bytes32 s) Elig(studentAddress,uniqueId)  external{
require(keccak256(bytes(role)) == keccak256(bytes("student")),"SSOA");
require(mentors[signer] == true,"SNM");
bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hash(studentAddress,_secretKey_1, _secretKey_2,role,uniqueId)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == signer,"INVALID_SIGNER");
student[studentAddress] = true;
isUniqueIdUsed[uniqueId] = true;
studentNonce[nonce] = studentAddress;
nonce++;
}

// mentor Hashing and Become Mentor

function becomeMentor(address mentorAddress,address signer,string memory _secretKey_1, string memory _secretKey_2, string memory role,uint256 uniqueId,uint8 v, bytes32 r, bytes32 s) Elig(mentorAddress,uniqueId)  external{
require(keccak256(bytes(role)) == keccak256(bytes("mentor")),"MSOA");
require(hod[signer] == true,"SNH");
bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hash(mentorAddress,_secretKey_1, _secretKey_2,role,uniqueId)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == signer,"INVALID_SIGNER");
mentors[mentorAddress] = true;
isUniqueIdUsed[uniqueId] = true;
mentorNonce[nonce] = mentorAddress;
nonce++;
}

function recover(bytes memory _signature,bytes32 _ethHash)public pure returns(address){
       (bytes32 r,bytes32 s,uint8 v) = split(_signature);
       return ecrecover(_ethHash,v,r,s);
}

function split(bytes memory  _signature)public pure returns(bytes32 r,bytes32 s,uint8 v){
       require(_signature.length == 65,"length is not proper");
         assembly {
          
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
}

   function isStudent(address _add)external view returns(bool){
    return student[_add];
}

   function isGrader(address _add)external view returns(bool){
    return grader[_add];
}

function isMentor(address _add)external view returns(bool){
    return mentors[_add];
}

function isHod(address _add) external view returns(bool){
    return hod[_add];
}
    function createProposalHashing(string memory ipfsCID,uint256 _nonce) public  pure returns(bytes32){
return (keccak256(abi.encode(
            keccak256(bytes("createProposal(string ipfsCid,uint256 _nonce)")),
            keccak256(bytes(ipfsCID)),
            _nonce
        )));
        
            }

            function getCurrNumProp()public view returns(uint){
                return currentNumOfProposal;
            }

   function openPropsal(string memory cid,uint8 v, bytes32 r, bytes32 s)external {
    bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
           createProposalHashing(cid,currentNumOfProposal)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == owner,"INVALID_SIGNER");

 proposal.push(Proposal(cid,ProposalStatus.pending,0,0));
 currentNumOfProposal++;
}


function closeProposalHashing(uint256 _ind,uint256 numOfUpVote,uint256 numOfDownVote) public pure returns (bytes32){
return (keccak256(abi.encode(
            keccak256(bytes("closeProposal(uint256 proposalNo,uint256 numOfUpVote,uint256 numOfDownVote)")),
          _ind,
          numOfUpVote,
          numOfDownVote
        )));
    }

function closeProposal(uint256 _ind,uint numOfUpVote,uint numOfDownVote,uint8 v, bytes32 r, bytes32 s)external {
    require(closeProposalNonce[_ind] == false,"PCA");
       bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
           closeProposalHashing(_ind,numOfUpVote,numOfDownVote)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == owner,"INVALID_SIGNER");

    proposal[_ind].numOfUpVote = numOfUpVote;
    proposal[_ind].numOfDownVote = numOfDownVote;
    if(numOfUpVote > numOfDownVote)
    proposal[_ind]._proposalStatus = ProposalStatus.approved;
    else
    proposal[_ind]._proposalStatus = ProposalStatus.rejected;

    closeProposalNonce[_ind] = true;
    
 }

 function getProposal(uint index)public  view returns(string memory){
    Proposal storage   _proposal = proposal[index];
    return(_proposal.ipfsCID);
 }

function isVerifyByrelayer(string memory _ipfsCID,bytes memory signature)public view returns (bool){
bytes32 _ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n59",_ipfsCID));
require(recover(signature,_ethHash) == relayer,"INVALID_RELAYER_SIGNER");
return true;
}

function mentorSignStudent(uint256 currentSemNum,string memory receiptNo)public pure returns(bytes32){
    return (keccak256(abi.encode(
            keccak256(bytes("signStudent(uint256 currentSemNum,string receiptNo)")),
            currentSemNum,
            keccak256(bytes(receiptNo))
        )));
} 

function isMentorSign(address mentor,uint256 currentSemNum,string memory receiptNo,uint8 v, bytes32 r, bytes32 s) public view {
require(mentors[mentor] == true,"MINE");
bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            mentorSignStudent(currentSemNum, receiptNo)
        ));
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == mentor,"INVALID_MENTOR");
}


function mintCert(address _student,address mentor,uint256 currentSemNum,string memory receiptNo,bytes memory mentorSignature, string memory _ipfsCID,bytes memory relayerSig,string memory degreeIpfs) external{
require(student[_student] == true,"YNS");
(bytes32 r,bytes32 s,uint8 v) = split(mentorSignature);
isMentorSign(mentor,currentSemNum,receiptNo,v,r,s);
isVerifyByrelayer(_ipfsCID,relayerSig);
semCertIssuance[_student][currentSemNum] = Certificate(_ipfsCID, true);
currentSemester[_student] = currentSemNum;
isUsedReceipt[receiptNo] = true;
if(currentSemNum == totalEndExamination)
mintDegreeCert(_student,degreeIpfs);
}


function mintDegreeCert(address _student,string memory _ipfsCID) public {
    require(student[_student] == true,"you are not have rights to mint degree!");
    require(currentSemester[_student] == totalEndExamination,"NEM");
    degreeCert[_student] = Certificate(_ipfsCID,true);


}

function hashUpd(address _add,string memory _cid,uint256 uniqueId) public  pure returns(bytes32){
return (keccak256(abi.encode(
keccak256(bytes("update(address account,string cid,uint256 uniqueId)")),
_add,
keccak256(bytes(_cid)),
uniqueId
)));
}

function editSemMarkSheet(address _student,string memory newIpfsCid,uint semesterNum,bytes memory sign,uint256 uniqueId)external {
    require(semesterNum <= currentSemester[_student] && isUniqueIdUsed[uniqueId] == false,"NEIOUM");

    bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hashUpd(_student,newIpfsCid,uniqueId)
        ));
(bytes32 r,bytes32 s,uint8 v) = split(sign);
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == owner,"INVALID_SIGNER");
    semCertIssuance[_student][semesterNum] = Certificate(newIpfsCid,true);
    isUniqueIdUsed[uniqueId] = true;

}

function editDegreeCert(address _student,string memory newIpfsCid,uint256 uniqueId,bytes memory sign)external {
require(totalEndExamination == currentSemester[_student]&& isUniqueIdUsed[uniqueId] == false,"NEIOUD");
   bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hashUpd(_student,newIpfsCid,uniqueId)
        ));
(bytes32 r,bytes32 s,uint8 v) = split(sign);
address recoveredAddress = ecrecover(digest, v, r, s);
require(recoveredAddress == owner,"INVALID_SIGNER");
degreeCert[_student] = Certificate(newIpfsCid,true);
 isUniqueIdUsed[uniqueId] = true;
}

function burnDegreeCert(address _student) external {
    require(degreeCert[_student].status == true,"NDB");
    degreeCert[_student] = Certificate("",false);
}

function returnChainId()public view returns(uint){
    return block.chainid;
}

function hashDomain(string memory name,string memory version,uint chainId,address verifyingContract) private pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            chainId,
            verifyingContract
        ));
    }

}

//bafkreiab2a6fs4ddy2my4v5ycu37mc6orsjveepcv7aw3g7bwnwy53ytke
// 0x420B7db4DBEbEa0f02E7D6E4Fa438080C0EF54C4 --mainet stuff