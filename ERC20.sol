// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

//struct model of EIP712Domain
struct EIP712Domain{
string name;
string version;
uint256 chainId;
address verifyingContract;
}
// struct model of Permit
struct Permit{
    address owner;
    address spender;
    uint256 value;
    uint nonces;
}

contract ERC20  {
 
    //total supply of the token
    uint256 public totalSupply;
    //mapping the token balance to user address
    mapping(address => uint256) public _balances;
    // allowance it map the owner address with spender and allowed token balance
    mapping(address => mapping(address => uint256)) public allowance;
    // name of the token
    string public name;
    //symbol of the token
    string public symbol;
    // decimals of token
    uint8 public decimals;
    //creator of this contract
    address public creator;
    //chain_id of this contract
    uint public CHAIN_ID;
    //initial domain separator
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;
    //nonces of the each users
     mapping(address => uint256) public nonces;
     //this contract initiate by this constructor
    constructor(string memory _name, string memory _symbol, uint8 _decimals,uint _totalSupply) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply;
        creator = msg.sender;
        CHAIN_ID = block.chainid;
        _balances[msg.sender] = totalSupply;
        INITIAL_DOMAIN_SEPARATOR = hashDomain(EIP712Domain({
            name: _name,
            version:"1",
            chainId:block.chainid,
            verifyingContract:address(this)
        }));
    }
/* 
@modifier 
    name
@usecase
    it help us to restrict the access of some function to others rather than creator of this contract 

*/
    modifier Creator() {
        require(creator == msg.sender);
        _;
    }

/*
@functionName
    transfer
@usecases
    it help us to transfer token to recipient
@params
    1. recipient - address of the recipient
    2. amount - amount you gonna to transfer
*/
    function transfer(address recipient, uint256 amount)
        external
        returns (bool)
    {
        // reducing the balance of the sender 
        _balances[msg.sender] -= amount;
        //increasing the balance of the recipient
        _balances[recipient] += amount;
        return true;
    }

/*
@functionName
    approve
@usecases
    it help us to approve spender specific amount of token to use(it mainly use on dex like uniswap) 
@params
    1. spender - address of the spender
    2. amount - amount you gonna to approve
*/

    function approve(address spender, uint256 amount) external returns (bool) {
        //assigning amount to the spender
        allowance[msg.sender][spender] = amount;
        return true;
    }

/*@functionName
    transferFrom
@usecases
Transfers tokens from a specified address to another address
@params
    1. spender - address of the spender
    2. spender - address of the spender
    3. amount - amount you gonna to transfer
*/

    function transferFrom(address sender, address recipient, uint256 amount)
        external
        returns (bool)
    {
    
         require(_balances[sender] >= amount, "Insufficient balance");
         allowance[sender][msg.sender] -= amount;
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        return true;
    }
/*@functionName
    mint
@usecases
it increase the total supply of the token. we can increase the total supply according to needs and demands
@params
    1. to - address of the person who gonna to hold newly minted token
    2. amount - amount you gonna to mint
*/
    function mint(address to, uint256 amount) external Creator {
        _balances[to] += amount;
        totalSupply += amount;
        
    }
/*@functionName
    burn
@usecases
it decrease the total supply of the token. we can decrease the total supply according to needs and demands
@params
    1. to - address of the person who gonna to reduce their token
    2. amount - amount you gonna to burn
*/
    function burn(address from, uint256 amount) external Creator {
        _balances[from] -= amount;
        totalSupply -= amount;
      
    }
/*@functionName
    balanceOf
@usecases
it return the balance of user
@params
account - address of the account 
*/

    function balanceOf(address account) public view returns(uint){
        return _balances[account];
    }


    function getChainid()public view returns (uint){
return CHAIN_ID;
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
      function hashDomain(EIP712Domain memory domain) private pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(domain.name)),
            keccak256(bytes(domain.version)),
            domain.chainId,
            domain.verifyingContract
           
        ));
    }
    
   /*
    @functionName 
        hashPermit
    @usecase
hashing the permitted message which is signed by user already
    @params
       1. owner - who signed the the message
       2. spender - who gonna to pay gas fees
       3. value - amount the token that spender gonna to use
   */

    function hashPermit(address owner,address receiver,address spender,uint256 value) private view returns(bytes32){
        return (keccak256(abi.encode(
            keccak256(bytes("Permit(address owner,address receiver,address spender,uint256 value,uint nonces)")),
            owner,
            receiver,
            spender,
            value,
            nonces[owner]

        )));
    }

   /*
    @functionName 
        permit
    @usecase
permitting the spender to use the approved token and pay gas fees for others. it allows gas less transaction
    @params
       1. owner - who signed the the message
       2. spender - who gonna to pay gas fees
       3. value - amount the token that spender gonna to use
       4. (uint8 v, bytes32 r, bytes32 s) - splitted signature which is signed by the owner(user who allows spender to do transaction or paying gas instead of him)
   */
    function permit(address owner,address spender,address receiver,uint256 value, uint8 v, bytes32 r, bytes32 s) public  {
bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            INITIAL_DOMAIN_SEPARATOR,
            hashPermit(owner,receiver,spender,value)
        ));

          address recoveredAddress = ecrecover(digest, v, r, s);
          require(recoveredAddress == owner,"INVALID_SIGNER");
          nonces[owner]++;
          allowance[owner][spender] = value;
    }
}
//contract gasless tokenTransfer

contract GaslessTokenTransfer {
    //owner of this contract - who gonna to pay the gas fees for others transaction
    address public creator;
    constructor(){
        creator = msg.sender;
    }
       /*
    @functionName 
        send
    @usecase
making others transfer and paying gas fees 
    @params
       1. erc20 - erc20 contract address
       2. spender - who gonna to pay gas fees
       3.receiver - who gonna to receive the token
       4. amnt - amount of token gonna transfer
   */
    function send(address erc20,address _owner,address spender,address receiver,uint256 amnt, uint8 v, bytes32 r, bytes32 s) external {
        require(creator == msg.sender);
               //inheriting(low level) the erc20 token smart contract and call the function tranferFrom
        ERC20(erc20).permit(_owner,spender,receiver,amnt,v,r,s);
        ERC20(erc20).transferFrom(_owner,receiver,amnt);
        
    }


}


//1711360465552