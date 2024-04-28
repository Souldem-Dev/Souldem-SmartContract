// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;
import "./Governance.sol";
contract GovernanceFactory{
    event newContract(address indexed createdBy, address indexed governanceAddress,uint length);
    // Governance contract declaration
   Governance[] public governance;
  
// storing chain id
uint internal immutable CHAIN_ID;
// initial domain serparator
bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;
// nonces
mapping(address=>uint)public nonces;
string public contractName;
// initializing the contract by getting contract name for set
constructor(string memory _contractName){
   CHAIN_ID = block.chainid;
   contractName = _contractName;
// hashing the domain
INITIAL_DOMAIN_SEPARATOR = hashDomain(_contractName,"1",block.chainid,address(this));

}

    /* 
    @functionName 
    hash
    @usecase
    hashing the message which is already signed by user(Coe) 
    @parameters
    1.wallet - address of the user(coe) wallet
    2._governanceName - name of the governance name (eg: consider governance as batch like BCA)
    3._totalEndExamination - total end examination of Coe (eg: BCA - 6 semeseter, B.tech - 8 semester)
    4. _batch - batch of this governance
    5. _nonces - nonce of the owner according to this  contract. Every nonce for each user is start from 0 only
    */
   function hash(address wallet,string memory _governanceName,uint256 _totalEndExamination,string memory _batch,uint256 _nonces) public pure returns(bytes32){
return (keccak256(abi.encode(
keccak256(bytes("CreateGovernance(address wallet,string governanceName,uint256 totalEndExamination,string batch,uint256 nonces)")),
wallet,
keccak256(bytes(_governanceName)),
_totalEndExamination,
keccak256(bytes(_batch)),
_nonces
)));
   }

   /* 
    @functionName 
    createNewContract
    @usecase
    this function help us to create the new Governance token 
    @parameters
    
    1._governanceName - name of the governance name (eg: consider governance as batch like BCA)
    2._totalEndExamination - total end examination of Coe (eg: BCA - 6 semeseter, B.tech - 8 semester)
    3. _batch - batch of this governance
    4. _owner - address of the user(coe) wallet
    5. _nonces - nonce of the owner according to this  contract. Every nonce for each user is start from 0 only
    6. uint8 v, bytes32 r, bytes32 s - splitted signature from the signer(_owner)
    */

   function createNewContract( string memory _governanceName,uint256 _totalEndExamination,string memory _batch,address _owner,uint8 v, bytes32 r, bytes32 s)public {
   // hasing the initial_domain_separator and messages(_owner,_governanceName...) for verification whether they sign
    bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hash(_owner,_governanceName,_totalEndExamination,_batch,nonces[_owner])
        ));
// recovering the public address of the owner by splitted signature (signed by owner) and digested hash
address recoveredAddress = ecrecover(digest, v, r, s);
//checking whether the recovered address is equal to owner(signer)
require(recoveredAddress == _owner,"INVALID_SIGNER");
    // construct the new governance
    Governance _governance = new Governance( _governanceName,_totalEndExamination,_owner,_batch);
    // creating and pushing the govenance
    governance.push(_governance);
    // increasing the nonces of the owner
    nonces[_owner]++;
    emit newContract(_owner,address(_governance),governance.length);

   }

   // returning blockchain id
function returnChainId()public view returns(uint){
    return block.chainid;
}
   /*
    @functionName 
        hashDomain
    @usecase
        it create the domain hash. it help us to prevent replay attack in different chain
    @params
        1. name - name of this contract
        2. version - version of this contract
        3. chainId -  chainid of the blockchain
        4. verifyingContract - address of this contract

   */
        
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


//0x6da448419Bd24C63fd69570F16543124c559856c
//Souldem-Factory-V1

