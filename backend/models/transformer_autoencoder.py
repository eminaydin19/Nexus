import numpy as np
import torch
from torch import nn

from backend.schema import N_FEATURES

TAIL_STEPS = 3


class _PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 100):
        super().__init__()
        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-np.log(10000.0) / d_model))
        pe = torch.zeros(max_len, 1, d_model)
        pe[:, 0, 0::2] = torch.sin(position * div_term)
        pe[:, 0, 1::2] = torch.cos(position * div_term)
        self.register_buffer('pe', pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x is [batch, seq_len, d_model]
        # pe is [max_len, 1, d_model]
        pe = self.pe[:x.size(1)]
        pe = pe.transpose(0, 1) # [1, seq_len, d_model]
        return x + pe


class _TransformerNetwork(nn.Module):
    def __init__(self, d_model: int = 32, nhead: int = 4, num_layers: int = 2):
        super().__init__()
        self.embedding = nn.Linear(N_FEATURES, d_model)
        self.pos_encoder = _PositionalEncoding(d_model)
        
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, batch_first=True, dim_feedforward=d_model*4, dropout=0.1)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        self.output = nn.Linear(d_model, N_FEATURES)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x)
        x = self.pos_encoder(x)
        out = self.transformer(x)
        return self.output(out)


class TransformerAutoEncoder:
    def __init__(self, d_model: int = 32, nhead: int = 4, num_layers: int = 2):
        self.d_model = d_model
        self.nhead = nhead
        self.num_layers = num_layers
        self.network = _TransformerNetwork(d_model, nhead, num_layers)
        self.network.eval()

    def fit(self, windows: np.ndarray, epochs: int, batch_size: int = 128, lr: float = 1e-3, seed: int = 42) -> float:
        torch.manual_seed(seed)
        data = torch.from_numpy(np.ascontiguousarray(windows, dtype=np.float32))
        optimizer = torch.optim.Adam(self.network.parameters(), lr=lr)
        self.network.train()
        loss_value = float("nan")
        for _ in range(epochs):
            order = torch.randperm(len(data))
            total, count = 0.0, 0
            for start in range(0, len(data), batch_size):
                batch = data[order[start : start + batch_size]]
                loss = nn.functional.mse_loss(self.network(batch), batch)
                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(self.network.parameters(), 1.0)
                optimizer.step()
                total += loss.item() * len(batch)
                count += len(batch)
            loss_value = total / count
        self.network.eval()
        return loss_value

    @torch.no_grad()
    def error(self, windows: np.ndarray) -> np.ndarray:
        x = torch.from_numpy(np.ascontiguousarray(windows, dtype=np.float32))
        diff = (self.network(x) - x)[:, -TAIL_STEPS:, :] ** 2
        return diff.mean(dim=(1, 2)).numpy()

    def to_state(self) -> dict:
        return {
            "d_model": self.d_model,
            "nhead": self.nhead,
            "num_layers": self.num_layers,
            "weights": {k: v.numpy() for k, v in self.network.state_dict().items()},
        }

    @classmethod
    def from_state(cls, state: dict) -> "TransformerAutoEncoder":
        model = cls(state["d_model"], state["nhead"], state["num_layers"])
        model.network.load_state_dict({k: torch.from_numpy(v) for k, v in state["weights"].items()})
        model.network.eval()
        return model
