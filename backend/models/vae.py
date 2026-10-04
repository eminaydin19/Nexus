import numpy as np
import torch
from torch import nn

from backend.schema import N_FEATURES

BETA = 0.1


class _Network(nn.Module):
    def __init__(self, hidden: int, latent: int):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(N_FEATURES, hidden), nn.ReLU(), nn.Linear(hidden, hidden), nn.ReLU())
        self.mu = nn.Linear(hidden, latent)
        self.logvar = nn.Linear(hidden, latent)
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden), nn.ReLU(), nn.Linear(hidden, hidden), nn.ReLU(), nn.Linear(hidden, N_FEATURES)
        )

    def forward(self, x: torch.Tensor):
        h = self.encoder(x)
        mu, logvar = self.mu(h), self.logvar(h)
        z = mu + torch.randn_like(mu) * torch.exp(0.5 * logvar) if self.training else mu
        return self.decoder(z), mu, logvar


class VAE:
    def __init__(self, hidden: int = 32, latent: int = 3):
        self.hidden = hidden
        self.latent = latent
        self.network = _Network(hidden, latent)
        self.network.eval()

    def fit(self, x: np.ndarray, epochs: int, batch_size: int = 256, lr: float = 3e-3, seed: int = 42) -> float:
        torch.manual_seed(seed)
        data = torch.from_numpy(np.ascontiguousarray(x, dtype=np.float32))
        optimizer = torch.optim.Adam(self.network.parameters(), lr=lr)
        self.network.train()
        loss_value = float("nan")
        for _ in range(epochs):
            order = torch.randperm(len(data))
            total, count = 0.0, 0
            for start in range(0, len(data), batch_size):
                batch = data[order[start : start + batch_size]]
                recon, mu, logvar = self.network(batch)
                recon_loss = nn.functional.mse_loss(recon, batch, reduction="sum") / len(batch)
                kl = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp()) / len(batch)
                loss = recon_loss + BETA * kl
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
    def error(self, x: np.ndarray) -> np.ndarray:
        t = torch.from_numpy(np.ascontiguousarray(x, dtype=np.float32))
        recon, _, _ = self.network(t)
        return ((recon - t) ** 2).mean(dim=1).numpy()

    def to_state(self) -> dict:
        return {
            "hidden": self.hidden,
            "latent": self.latent,
            "weights": {k: v.numpy() for k, v in self.network.state_dict().items()},
        }

    @classmethod
    def from_state(cls, state: dict) -> "VAE":
        model = cls(state["hidden"], state["latent"])
        model.network.load_state_dict({k: torch.from_numpy(v) for k, v in state["weights"].items()})
        model.network.eval()
        return model
