// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;
import "./GovernanceFactory.sol";
contract BaseFactory{
    GovernanceFactory[] public governanceFactory;
    mapping(address=>address) public ownedFactory;
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    constructor(){
INITIAL_DOMAIN_SEPARATOR = hashDomain("BASE_FACTORY","1",block.chainid,address(this));

    }
   function hash(address wallet,string memory _universityName) public pure returns(bytes32){
return (keccak256(abi.encode(
keccak256(bytes("Create(address wallet,string universityName)")),
wallet,
keccak256(bytes(_universityName))
)));
   }

    function createMyOwnFactory(string memory _universityName,address _owner,uint8 v, bytes32 r, bytes32 s)public {
        require(ownedFactory[_owner] == address(0),"you already created");
        // hasing the initial_domain_separator and messages(_owner,_governanceName...) for verification whether they sign
    bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hash(_owner,_universityName)
        ));
// recovering the public address of the owner by splitted signature (signed by owner) and digested hash
address recoveredAddress = ecrecover(digest, v, r, s);
//checking whether the recovered address is equal to owner(signer)
require(recoveredAddress == _owner,"INVALID_SIGNER");
// creating Factory contract
        GovernanceFactory _governance = new GovernanceFactory(_universityName);
        governanceFactory.push(_governance);
        ownedFactory[_owner] = address(_governance);
    }

function getContractAdd(address _owner)public view returns(address){
    return ownedFactory[_owner];
}
       // returning blockchain id
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