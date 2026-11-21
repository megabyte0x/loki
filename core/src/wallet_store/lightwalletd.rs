use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    time::Duration,
};

use prost::{
    bytes::{Buf, Bytes},
    Message,
};
use tonic::{
    client::Grpc,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    transport::Channel,
    Request, Status,
};
use zcash_client_backend::{
    data_api::chain::CommitmentTreeRoot,
    proto::{
        compact_formats::CompactBlock,
        service::{
            compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange,
            GetSubtreeRootsArg, ShieldedProtocol, SubtreeRoot,
        },
    },
};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::BlockHeight;

use loki_signer_core::chain_scan::validate_compact_block;

const DEADLINE: Duration = Duration::from_secs(30);
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 32 * 1024 * 1024;
const MAX_BLOCKS: u64 = 500;
const ROOTS_PER_PAGE: usize = 512;
// 32-bit tree sizes and 16-level subtrees.
const MAX_ROOTS: u32 = u32::MAX >> 16;

pub struct Lightwalletd {
    channel: Channel,
    unary: CompactTxStreamerClient<Channel>,
}

impl Lightwalletd {
    pub fn new(channel: Channel) -> Self {
        Self {
            unary: CompactTxStreamerClient::new(channel.clone()),
            channel,
        }
    }

    pub(super) async fn blocks(
        &self,
        first: BlockHeight,
        last: BlockHeight,
    ) -> Result<Vec<CompactBlock>, String> {
        let (start, end) = (u64::from(first), u64::from(last));
        if start == 0 || end >= u64::from(u32::MAX) || end < start || end - start >= MAX_BLOCKS {
            return Err("invalid lightwalletd block range".into());
        }
        let count = (end - start + 1) as usize;
        let messages = self
            .read_stream(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
                BlockRange {
                    start: Some(BlockId {
                        height: start,
                        hash: vec![],
                    }),
                    end: Some(BlockId {
                        height: end,
                        hash: vec![],
                    }),
                    pool_types: vec![],
                },
                count,
                MAX_STREAM_BYTES,
            )
            .await?;
        if messages.len() != count {
            return Err(format!(
                "lightwalletd returned {} of {count} requested blocks",
                messages.len()
            ));
        }
        let mut blocks: Vec<CompactBlock> = Vec::with_capacity(count);
        for (requested, bytes) in (start..=end).zip(messages) {
            let mut block =
                CompactBlock::decode(bytes).map_err(|e| format!("decode compact block: {e}"))?;
            if block.height != requested {
                return Err(format!(
                    "lightwalletd returned block {} instead of {requested}",
                    block.height
                ));
            }
            validate_compact_block(&mut block)?;
            if blocks
                .last()
                .is_some_and(|prev| block.prev_hash != prev.hash)
            {
                return Err("lightwalletd returned inconsistent block parents".into());
            }
            blocks.push(block);
        }
        Ok(blocks)
    }

    pub(super) async fn subtree_roots<H: HashSer>(
        &self,
        protocol: ShieldedProtocol,
        tip: BlockHeight,
    ) -> Result<Vec<CommitmentTreeRoot<H>>, String> {
        tokio::time::timeout(Duration::from_secs(90), async {
            let mut roots = Vec::new();
            let mut last_height = 0;
            loop {
                let (page, done) = self
                    .subtree_page(protocol, roots.len() as u32, tip, &mut last_height)
                    .await?;
                roots.extend(page);
                if done {
                    return Ok(roots);
                }
            }
        })
        .await
        .map_err(|_| "lightwalletd subtree paging deadline exceeded".to_string())?
    }

    async fn subtree_page<H: HashSer>(
        &self,
        protocol: ShieldedProtocol,
        start: u32,
        tip: BlockHeight,
        last_height: &mut u64,
    ) -> Result<(Vec<CommitmentTreeRoot<H>>, bool), String> {
        let limit = usize::min(ROOTS_PER_PAGE, (MAX_ROOTS - start + 1) as usize);
        let page = self
            .read_stream(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetSubtreeRoots",
                GetSubtreeRootsArg {
                    start_index: start,
                    shielded_protocol: protocol as i32,
                    max_entries: limit as u32,
                },
                limit,
                limit * 128,
            )
            .await?;
        if start as usize + page.len() > MAX_ROOTS as usize {
            return Err("lightwalletd returned too many subtree roots".into());
        }
        let done = page.len() < limit;
        let roots = page
            .into_iter()
            .map(|bytes| {
                let root =
                    SubtreeRoot::decode(bytes).map_err(|e| format!("decode subtree root: {e}"))?;
                let height = root.completing_block_height;
                if height < *last_height
                    || height > u64::from(tip)
                    || root.root_hash.len() != 32
                    || root.completing_block_hash.len() != 32
                {
                    return Err("lightwalletd returned an invalid subtree root".into());
                }
                *last_height = height;
                let hash = H::read(root.root_hash.as_slice())
                    .map_err(|e| format!("read subtree root: {e}"))?;
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(height as u32),
                    hash,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok((roots, done))
    }

    async fn read_stream<Q: Message + 'static>(
        &self,
        path: &'static str,
        request: Q,
        count: usize,
        max_bytes: usize,
    ) -> Result<Vec<Bytes>, String> {
        let result = tokio::time::timeout(DEADLINE, async {
            let mut grpc = Grpc::new(self.channel.clone())
                .max_decoding_message_size(MAX_MESSAGE_BYTES.min(max_bytes));
            grpc.ready()
                .await
                .map_err(|err| Status::unavailable(err.to_string()))?;
            let mut request = Request::new(request);
            request.set_timeout(DEADLINE);
            let response = grpc
                .server_streaming(
                    request,
                    path.parse().expect("static RPC path"),
                    WireCodec(PhantomData),
                )
                .await?;
            let header_ok = response
                .metadata()
                .get("grpc-status")
                .is_some_and(|s| s == "0");
            let mut stream = response.into_inner();
            let mut messages = Vec::new();
            let mut bytes = 0;
            while let Some(message) = stream.message().await? {
                bytes += message.len() + 5; // Include the envelope and any unknown protobuf fields.
                if bytes > max_bytes || messages.len() >= count {
                    return Err(Status::resource_exhausted(
                        "lightwalletd response exceeds its stream budget",
                    ));
                }
                messages.push(message);
            }
            if !(messages.is_empty() && header_ok)
                && !stream
                    .trailers()
                    .await?
                    .and_then(|t| t.get("grpc-status").cloned())
                    .is_some_and(|s| s == "0")
            {
                return Err(Status::unknown("missing successful grpc-status"));
            }
            Ok(messages)
        })
        .await
        .map_err(|_| format!("lightwalletd {path}: deadline exceeded"))?;
        result.map_err(|err| format!("lightwalletd {path}: {err}"))
    }
}

impl Deref for Lightwalletd {
    type Target = CompactTxStreamerClient<Channel>;
    fn deref(&self) -> &Self::Target {
        &self.unary
    }
}
impl DerefMut for Lightwalletd {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.unary
    }
}

// Count the wire bytes before protobuf decoding can discard unknown fields or expand allocations.
struct WireCodec<Q>(PhantomData<Q>);
struct WireBytes;

impl<Q: Message + 'static> Codec for WireCodec<Q> {
    type Encode = Q;
    type Decode = Bytes;
    type Encoder = Self;
    type Decoder = WireBytes;
    fn encoder(&mut self) -> Self::Encoder {
        Self(PhantomData)
    }
    fn decoder(&mut self) -> Self::Decoder {
        WireBytes
    }
}
impl<Q: Message> Encoder for WireCodec<Q> {
    type Item = Q;
    type Error = Status;
    fn encode(&mut self, item: Q, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(dst)
            .map_err(|e| Status::internal(e.to_string()))
    }
}
impl Decoder for WireBytes {
    type Item = Bytes;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        Ok(Some(src.copy_to_bytes(src.remaining())))
    }
}
