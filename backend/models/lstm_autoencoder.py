import numpy as np
import torch
from torch import nn

from backend.schema import N_FEATURES

TAIL_STEPS = 3


class _Network(nn.Module):
    def __init__(self, hidden: int, latent: int):
        super().__init__()
        self.encoder = nn.LSTM(N_FEATURES, hidden, batch_first=True)
        self.to_latent = nn.Linear(hidden, latent)
        self.from_latent = nn.Linear(latent, hidden)
        self.decoder = nn.LSTM(hidden, hidden, batch_first=True)
        self.output = nn.Linear(hidden, N_FEATURES)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h, _) = self.encoder(x)
        z = self.to_latent(h[-1])
        repeated = self.from_latent(z).unsqueeze(1).expand(-1, x.size(1), -1)
        decoded, _ = self.decoder(repeated)
        return self.output(decoded)


class LSTMAutoEncoder:
    def __init__(self, hidden: int = 32, latent: int = 8):
        self.hidden = hidden
        self.latent = latent
        self.network = _Network(hidden, latent)
        self.network.eval()

    def fit(self, windows: np.ndarray, epochs: int, batch_size: int = 128, lr: float = 2e-3, seed: int = 42) -> float:
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
            "hidden": self.hidden,
            "latent": self.latent,
            "weights": {k: v.numpy() for k, v in self.network.state_dict().items()},
        }

    @classmethod
    def from_state(cls, state: dict) -> "LSTMAutoEncoder":
        model = cls(state["hidden"], state["latent"])
        model.network.load_state_dict({k: torch.from_numpy(v) for k, v in state["weights"].items()})
        model.network.eval()
        return model
