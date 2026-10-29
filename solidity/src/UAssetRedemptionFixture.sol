// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Test-only ERC-20 with finite allowances, used by the Safe integration test.
contract RedemptionTokenFixture {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// Test-only vault implementing the production redeem ABI and sender semantics.
/// Rates are fixed at $1 and $2 to check per-asset amounts and minimum payouts.
contract UAssetRedemptionFixture {
    RedemptionTokenFixture public immutable tokenA = new RedemptionTokenFixture();
    RedemptionTokenFixture public immutable tokenB = new RedemptionTokenFixture();
    RedemptionTokenFixture public immutable USDC = new RedemptionTokenFixture();

    function fundUser(address user) external {
        tokenA.mint(user, 10e18);
        tokenB.mint(user, 10e18);
        USDC.mint(address(this), 30e6);
    }

    function redeem(address asset, uint256 amount, uint256 minimumUSDCAmount)
        external returns (uint256 usdcAmount)
    {
        require(asset == address(tokenA) || asset == address(tokenB), "Unsupported asset");
        usdcAmount = amount * (asset == address(tokenA) ? 1 : 2) / 1e12;
        require(usdcAmount > 0 && usdcAmount >= minimumUSDCAmount, "Payout below minimum");
        require(USDC.balanceOf(address(this)) >= usdcAmount, "Insufficient liquidity");
        require(RedemptionTokenFixture(asset).transferFrom(msg.sender, address(this), amount));
        require(USDC.transfer(msg.sender, usdcAmount));
    }
}
