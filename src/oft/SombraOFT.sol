// SPDX-License-Identifier: MIT

// Adapted from https://github.com/LayerZero-Labs/solidity-examples/blob/main/contracts/token/oft/extension/ProxyOFT.sol
// Modified to fit the Sombra token.

pragma solidity ^0.8.0;

import "./OFTCore.sol";

interface ISombraToken {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

contract ProxyOFT is OFTCore {
    ISombraToken internal immutable innerToken;

    constructor(address _lzEndpoint, address _token) OFTCore(_lzEndpoint) {
        innerToken = ISombraToken(_token);
    }

    function circulatingSupply() public view virtual override returns (uint) {
        unchecked {
            return innerToken.totalSupply();
        }
    }

    function token() public view virtual override returns (address) {
        return address(innerToken);
    }

    function _debitFrom(address _from, uint16, bytes memory, uint _amount) internal virtual override returns(uint) {
        require(_from == _msgSender(), "ProxyOFT: owner is not send caller");
        innerToken.burn(_from, _amount);
        return _amount;
    }

    function _creditTo(uint16, address _toAddress, uint _amount) internal virtual override returns(uint) {
        uint before = innerToken.balanceOf(_toAddress);
        innerToken.mint(_toAddress, _amount);
        return innerToken.balanceOf(_toAddress) - before;
    }
}
