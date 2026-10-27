//! Satoris on-chain program.
//!
//! - **Registry & staking**: GPU providers register a node with its sealing key
//!   and launch measurement, and lock stake in a program-owned vault.
//! - **Attestation records**: an attestation authority (an off-chain verifier
//!   set; TDX/SNP quote verification is too heavy to run on-chain) posts the hash
//!   of verified evidence, the trust tier and an expiry for each node.
//! - **Receipt anchoring**: the gateway posts Merkle roots of job receipts, so any
//!   client can prove that a given job, price and node were recorded.
//! - **Slashing**: the slash authority can move stake from a node's vault to the
//!   treasury, citing a reason hash (failed re-attestation, bad output proof...).
//!
//! No prompts, completions or user identifiers are ever written on-chain.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

pub const CONFIG_SEED: &[u8] = b"config";
pub const NODE_SEED: &[u8] = b"node";
pub const VAULT_SEED: &[u8] = b"vault";
pub const BATCH_SEED: &[u8] = b"batch";

pub const TIER_UNTRUSTED: u8 = 0;
pub const TIER_TEE_CPU: u8 = 1;
pub const TIER_TEE_GPU: u8 = 2;

#[program]
pub mod satoris {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, params: ConfigParams) -> Result<()> {
        require!(params.unbonding_seconds >= 0, SatorisError::InvalidParam);
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.stake_mint = ctx.accounts.stake_mint.key();
        config.treasury = ctx.accounts.treasury.key();
        config.attestation_authority = params.attestation_authority;
        config.receipt_authority = params.receipt_authority;
        config.slash_authority = params.slash_authority;
        config.min_stake = params.min_stake;
        config.unbonding_seconds = params.unbonding_seconds;
        config.batch_count = 0;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    /// Register a node and lock `stake` tokens. The node starts untrusted until
    /// the attestation authority records a verified quote for it.
    pub fn register_node(
        ctx: Context<RegisterNode>,
        node_id: [u8; 32],
        sealing_key: [u8; 32],
        measurement: [u8; 48],
        endpoint_hash: [u8; 32],
        stake: u64,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(stake >= config.min_stake, SatorisError::StakeTooLow);

        transfer_into_vault(
            &ctx.accounts.token_program,
            &ctx.accounts.owner_tokens,
            &ctx.accounts.vault,
            &ctx.accounts.stake_mint,
            &ctx.accounts.owner,
            stake,
        )?;

        let node = &mut ctx.accounts.node;
        node.owner = ctx.accounts.owner.key();
        node.node_id = node_id;
        node.sealing_key = sealing_key;
        node.measurement = measurement;
        node.endpoint_hash = endpoint_hash;
        node.stake = stake;
        node.tier = TIER_UNTRUSTED;
        node.evidence_hash = [0; 32];
        node.attested_at = 0;
        node.attestation_expires_at = 0;
        node.unbonding_at = 0;
        node.slashed_total = 0;
        node.bump = ctx.bumps.node;
        node.vault_bump = ctx.bumps.vault;
        emit!(NodeRegistered { node: node.key(), owner: node.owner, stake });
        Ok(())
    }

    pub fn add_stake(ctx: Context<AddStake>, amount: u64) -> Result<()> {
        require!(amount > 0, SatorisError::InvalidParam);
        transfer_into_vault(
            &ctx.accounts.token_program,
            &ctx.accounts.owner_tokens,
            &ctx.accounts.vault,
            &ctx.accounts.stake_mint,
            &ctx.accounts.owner,
            amount,
        )?;
        let node = &mut ctx.accounts.node;
        node.stake = node.stake.checked_add(amount).ok_or(SatorisError::Overflow)?;
        Ok(())
    }

    /// Rotate the sealing key / image after a redeploy. Trust resets until re-attested.
    pub fn update_node(
        ctx: Context<UpdateNode>,
        sealing_key: [u8; 32],
        measurement: [u8; 48],
        endpoint_hash: [u8; 32],
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;
        node.sealing_key = sealing_key;
        node.measurement = measurement;
        node.endpoint_hash = endpoint_hash;
        node.tier = TIER_UNTRUSTED;
        node.attestation_expires_at = 0;
        Ok(())
    }

    /// Record a verified attestation. The evidence itself lives off-chain;
    /// anyone can fetch it from the node and check it hashes to `evidence_hash`.
    pub fn record_attestation(
        ctx: Context<RecordAttestation>,
        evidence_hash: [u8; 32],
        measurement: [u8; 48],
        sealing_key: [u8; 32],
        tier: u8,
        expires_at: i64,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(tier == TIER_TEE_CPU || tier == TIER_TEE_GPU, SatorisError::InvalidParam);
        require!(expires_at > now, SatorisError::InvalidParam);
        let node = &mut ctx.accounts.node;
        require!(node.unbonding_at == 0, SatorisError::NodeUnbonding);
        // The quote must be for the image and key the owner registered.
        require!(node.measurement == measurement, SatorisError::MeasurementMismatch);
        require!(node.sealing_key == sealing_key, SatorisError::KeyMismatch);
        node.evidence_hash = evidence_hash;
        node.tier = tier;
        node.attested_at = now;
        node.attestation_expires_at = expires_at;
        emit!(NodeAttested { node: node.key(), tier, evidence_hash, expires_at });
        Ok(())
    }

    /// Anchor a Merkle root of job receipts (see gateway `receiptLeaf`/`merkleRoot`).
    pub fn anchor_receipts(
        ctx: Context<AnchorReceipts>,
        root: [u8; 32],
        count: u32,
        first_at: i64,
        last_at: i64,
    ) -> Result<()> {
        require!(count > 0 && first_at <= last_at, SatorisError::InvalidParam);
        let config = &mut ctx.accounts.config;
        let batch = &mut ctx.accounts.batch;
        batch.index = config.batch_count;
        batch.root = root;
        batch.count = count;
        batch.first_at = first_at;
        batch.last_at = last_at;
        batch.anchored_at = Clock::get()?.unix_timestamp;
        batch.bump = ctx.bumps.batch;
        config.batch_count = config.batch_count.checked_add(1).ok_or(SatorisError::Overflow)?;
        emit!(ReceiptsAnchored { index: batch.index, root, count });
        Ok(())
    }

    /// Move `amount` of a node's stake to the treasury. Trust is revoked.
    pub fn slash(ctx: Context<Slash>, amount: u64, reason_hash: [u8; 32]) -> Result<()> {
        let node = &mut ctx.accounts.node;
        let amount = amount.min(node.stake);
        require!(amount > 0, SatorisError::InvalidParam);
        transfer_from_vault(
            &ctx.accounts.token_program,
            &ctx.accounts.vault,
            &ctx.accounts.treasury,
            &ctx.accounts.stake_mint,
            node,
            amount,
        )?;
        node.stake -= amount;
        node.slashed_total = node.slashed_total.checked_add(amount).ok_or(SatorisError::Overflow)?;
        node.tier = TIER_UNTRUSTED;
        node.attestation_expires_at = 0;
        emit!(NodeSlashed { node: node.key(), amount, reason_hash });
        Ok(())
    }

    /// Stop taking jobs and start the unbonding clock. Stake stays slashable meanwhile.
    pub fn begin_unbonding(ctx: Context<OwnerNode>) -> Result<()> {
        let node = &mut ctx.accounts.node;
        require!(node.unbonding_at == 0, SatorisError::NodeUnbonding);
        node.unbonding_at = Clock::get()?.unix_timestamp;
        node.tier = TIER_UNTRUSTED;
        node.attestation_expires_at = 0;
        Ok(())
    }

    pub fn withdraw_stake(ctx: Context<WithdrawStake>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let config = &ctx.accounts.config;
        let node = &mut ctx.accounts.node;
        require!(node.unbonding_at != 0, SatorisError::NotUnbonding);
        require!(
            now >= node.unbonding_at.saturating_add(config.unbonding_seconds),
            SatorisError::StillUnbonding
        );
        let amount = node.stake;
        transfer_from_vault(
            &ctx.accounts.token_program,
            &ctx.accounts.vault,
            &ctx.accounts.owner_tokens,
            &ctx.accounts.stake_mint,
            node,
            amount,
        )?;
        node.stake = 0;
        Ok(())
    }
}

fn transfer_into_vault<'info>(
    token_program: &Interface<'info, TokenInterface>,
    from: &InterfaceAccount<'info, TokenAccount>,
    vault: &InterfaceAccount<'info, TokenAccount>,
    mint: &InterfaceAccount<'info, Mint>,
    authority: &Signer<'info>,
    amount: u64,
) -> Result<()> {
    token_interface::transfer_checked(
        CpiContext::new(
            token_program.key(),
            TransferChecked {
                from: from.to_account_info(),
                mint: mint.to_account_info(),
                to: vault.to_account_info(),
                authority: authority.to_account_info(),
            },
        ),
        amount,
        mint.decimals,
    )
}

/// The vault's authority is the node PDA itself, so only this program can move stake.
fn transfer_from_vault<'info>(
    token_program: &Interface<'info, TokenInterface>,
    vault: &InterfaceAccount<'info, TokenAccount>,
    to: &InterfaceAccount<'info, TokenAccount>,
    mint: &InterfaceAccount<'info, Mint>,
    node: &Account<'info, Node>,
    amount: u64,
) -> Result<()> {
    let seeds: &[&[u8]] = &[NODE_SEED, node.owner.as_ref(), node.node_id.as_ref(), &[node.bump]];
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            token_program.key(),
            TransferChecked {
                from: vault.to_account_info(),
                mint: mint.to_account_info(),
                to: to.to_account_info(),
                authority: node.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        mint.decimals,
    )
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub stake_mint: Pubkey,
    pub treasury: Pubkey,
    pub attestation_authority: Pubkey,
    pub receipt_authority: Pubkey,
    pub slash_authority: Pubkey,
    pub min_stake: u64,
    pub unbonding_seconds: i64,
    pub batch_count: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Node {
    pub owner: Pubkey,
    pub node_id: [u8; 32],
    /// X25519 key clients seal prompts to; must match the attested report_data.
    pub sealing_key: [u8; 32],
    /// Launch measurement of the approved node image.
    pub measurement: [u8; 48],
    /// sha256 of the node's public endpoint URL.
    pub endpoint_hash: [u8; 32],
    pub stake: u64,
    pub tier: u8,
    pub evidence_hash: [u8; 32],
    pub attested_at: i64,
    pub attestation_expires_at: i64,
    pub unbonding_at: i64,
    pub slashed_total: u64,
    pub bump: u8,
    pub vault_bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ReceiptBatch {
    pub index: u64,
    pub root: [u8; 32],
    pub count: u32,
    pub first_at: i64,
    pub last_at: i64,
    pub anchored_at: i64,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ConfigParams {
    pub attestation_authority: Pubkey,
    pub receipt_authority: Pubkey,
    pub slash_authority: Pubkey,
    pub min_stake: u64,
    pub unbonding_seconds: i64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    pub stake_mint: InterfaceAccount<'info, Mint>,
    #[account(token::mint = stake_mint)]
    pub treasury: InterfaceAccount<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(node_id: [u8; 32])]
pub struct RegisterNode<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = stake_mint)]
    pub config: Account<'info, Config>,
    #[account(
        init,
        payer = owner,
        space = 8 + Node::INIT_SPACE,
        seeds = [NODE_SEED, owner.key().as_ref(), node_id.as_ref()],
        bump
    )]
    pub node: Account<'info, Node>,
    #[account(
        init,
        payer = owner,
        seeds = [VAULT_SEED, node.key().as_ref()],
        bump,
        token::mint = stake_mint,
        token::authority = node,
        token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, token::mint = stake_mint, token::authority = owner)]
    pub owner_tokens: InterfaceAccount<'info, TokenAccount>,
    pub stake_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AddStake<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = stake_mint)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = owner, constraint = node.unbonding_at == 0 @ SatorisError::NodeUnbonding)]
    pub node: Account<'info, Node>,
    #[account(mut, seeds = [VAULT_SEED, node.key().as_ref()], bump = node.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, token::mint = stake_mint, token::authority = owner)]
    pub owner_tokens: InterfaceAccount<'info, TokenAccount>,
    pub stake_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct UpdateNode<'info> {
    pub owner: Signer<'info>,
    #[account(mut, has_one = owner)]
    pub node: Account<'info, Node>,
}

#[derive(Accounts)]
pub struct OwnerNode<'info> {
    pub owner: Signer<'info>,
    #[account(mut, has_one = owner)]
    pub node: Account<'info, Node>,
}

#[derive(Accounts)]
pub struct RecordAttestation<'info> {
    pub attestation_authority: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = attestation_authority)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub node: Account<'info, Node>,
}

#[derive(Accounts)]
pub struct AnchorReceipts<'info> {
    #[account(mut)]
    pub receipt_authority: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = receipt_authority)]
    pub config: Account<'info, Config>,
    #[account(
        init,
        payer = receipt_authority,
        space = 8 + ReceiptBatch::INIT_SPACE,
        seeds = [BATCH_SEED, config.batch_count.to_le_bytes().as_ref()],
        bump
    )]
    pub batch: Account<'info, ReceiptBatch>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Slash<'info> {
    pub slash_authority: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = slash_authority, has_one = treasury, has_one = stake_mint)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub node: Account<'info, Node>,
    #[account(mut, seeds = [VAULT_SEED, node.key().as_ref()], bump = node.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub treasury: InterfaceAccount<'info, TokenAccount>,
    pub stake_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawStake<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = stake_mint)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = owner)]
    pub node: Account<'info, Node>,
    #[account(mut, seeds = [VAULT_SEED, node.key().as_ref()], bump = node.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, token::mint = stake_mint, token::authority = owner)]
    pub owner_tokens: InterfaceAccount<'info, TokenAccount>,
    pub stake_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[event]
pub struct NodeRegistered {
    pub node: Pubkey,
    pub owner: Pubkey,
    pub stake: u64,
}

#[event]
pub struct NodeAttested {
    pub node: Pubkey,
    pub tier: u8,
    pub evidence_hash: [u8; 32],
    pub expires_at: i64,
}

#[event]
pub struct ReceiptsAnchored {
    pub index: u64,
    pub root: [u8; 32],
    pub count: u32,
}

#[event]
pub struct NodeSlashed {
    pub node: Pubkey,
    pub amount: u64,
    pub reason_hash: [u8; 32],
}

#[error_code]
pub enum SatorisError {
    #[msg("invalid parameter")]
    InvalidParam,
    #[msg("stake is below the configured minimum")]
    StakeTooLow,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("attested measurement does not match the registered image")]
    MeasurementMismatch,
    #[msg("attested sealing key does not match the registered key")]
    KeyMismatch,
    #[msg("node is unbonding")]
    NodeUnbonding,
    #[msg("node is not unbonding")]
    NotUnbonding,
    #[msg("unbonding period has not elapsed")]
    StillUnbonding,
}
