# Dynamic Vickrey Auction for Heterogeneous CPU Scheduler

## 1. System Model

### 1.1 Hardware Platform

A heterogeneous CPU with two core classes:

- **P-cores** (Performance): set $\mathcal{P} = \{P_1, \ldots, P_{K_P}\}$, $|\mathcal{P}| = K_P$
- **E-cores** (Efficiency): set $\mathcal{E} = \{E_1, \ldots, E_{K_E}\}$, $|\mathcal{E}| = K_E$
- Total cores: $K = K_P + K_E$

Time is discrete: $t = 1, 2, 3, \ldots$ (scheduler ticks, time quanta).

At each moment $t$ every core is a **perishable good**: unused quanta are lost.

### 1.2 Tasks as Agents

At each moment $t$ the system contains a set of tasks $\mathcal{N}^t$. New tasks arrive stochastically: the set of newly arrived tasks $N_t$ is an i.i.d. random variable.

Each task $i$ has a private type $\theta_i = (v_i, l_i) \in \Theta$, where:

- $v_i \in [0, \bar{V}]$ — **valuation** (value of completion to the system/user)
- $l_i \in \{1, \ldots, L\}$ — **required number of quanta** (task length)

All cores (P and E) share a single ISA, so any task can run on any core. The difference between P-core and E-core is solely in quantum cost and execution speed. Core type assignment is an auction decision, not a task constraint.

Task $i$ receives utility $v_i$ **only** if it holds a core for all $l_i$ consecutive quanta (analogous to Sano's model where an agent earns profit only upon full contract completion). If task $i$ is assigned to an E-core, its effective length is scaled by a slowdown factor: a task requiring $l_i$ quanta on a P-core requires $\lceil l_i \cdot \sigma \rceil$ quanta on an E-core, where $\sigma = \eta_P / \eta_E > 1$ is the performance ratio.

### 1.3 Task Budgets

Each task $i$ enters the system with an initial budget $B_i > 0$. Budgets are determined by priority/service class:

| Class | Budget | Interpretation |
|-------|--------|----------------|
| Real-time | $B_{RT} \gg 1$ | Guaranteed execution |
| Interactive | $B_{int}$ | High priority |
| Batch | $B_{batch}$ | Low priority |
| Background | $B_{bg} \approx 0$ | Residual resources |

A task can execute only if its total payments do not exceed its budget:

$$\sum_{s=t}^{t+m_i-1} p_i^s \leq B_i$$

---

## 2. MDP Model (after Leon & Etesami)

### 2.1 State Space

State $s^t \in \mathcal{S}$ at time $t$ describes the current system configuration:

$$s^t = \bigl(\mathbf{x}^t,\; \mathbf{b}^t,\; \boldsymbol{\omega}^t\bigr)$$

where:
- $\mathbf{x}^t = (x_1^t, \ldots, x_K^t) \in \{0, 1, \ldots, L-1\}^K$ — vector of **remaining periods** for each core (quanta until release; $x_k^t = 0$ means "core is free")
- $\mathbf{b}^t = (b_1^t, \ldots, b_{|\mathcal{N}^t|}^t)$ — vector of remaining budgets of active tasks
- $\boldsymbol{\omega}^t$ — external factors (temperature, power consumption, memory load)

Free P-cores at time $t$:

$$K_P^t = K_P - |\{k \in \mathcal{P} : x_k^t \geq 1\}|$$

Free E-cores at time $t$:

$$K_E^t = K_E - |\{k \in \mathcal{E} : x_k^t \geq 1\}|$$

### 2.2 Action Space

Action $a^t \in \mathcal{A}$ is an allocation: for each task $i \in \mathcal{N}^t$:

$$a_i^t = (a_{i,P}^t, a_{i,E}^t) \in \{0,1\}^2, \quad a_{i,P}^t + a_{i,E}^t \leq 1$$

where $a_{i,P}^t = 1$ means "task $i$ receives a P-core", $a_{i,E}^t = 1$ means "receives an E-core".

Feasibility constraints:

$$\sum_{i \in \mathcal{N}^t} a_{i,P}^t \leq K_P^t, \qquad \sum_{i \in \mathcal{N}^t} a_{i,E}^t \leq K_E^t$$

### 2.3 Transition Function

$$s^{t+1} = G(s^t, a^t, N_{t+1})$$

Core $k$ assigned to task $i$ with length $l_i$ transitions to $x_k^{t+1} = l_i - 1$. All other cores: $x_k^{t+1} = \max(x_k^t - 1, 0)$.

### 2.4 Reward Functions

For each task $i$ (bidder agent):

$$r_i(s, a) = \begin{cases} v_i & \text{if task } i \text{ receives a core and this is the first quantum of the contract} \\ 0 & \text{otherwise} \end{cases}$$

For the scheduler (seller), reward is a resource utilization fee:

$$r_0(s, a) = \sum_{k \in \mathcal{P}} \mu_P \cdot \mathbb{1}[x_k \geq 1] + \sum_{k \in \mathcal{E}} \mu_E \cdot \mathbb{1}[x_k \geq 1]$$

where $\mu_P, \mu_E$ are base utilization rates ($\mu_E < \mu_P$, since E-cores are cheaper to operate).

---

## 3. Contracts and Pricing (after Sano)

### 3.1 Simple Contracts

When task $i$ arrives at time $t$, the scheduler offers it a **contract**:

$$z_i^t = (a_i, m_i, p_i, \kappa_i)$$

where:
- $a_i \in [0,1]$ — probability of receiving a core
- $m_i$ — contract length (number of quanta); depends on core type: $m_i = l_i$ on P-core, $m_i = \lceil l_i \cdot \sigma \rceil$ on E-core
- $p_i$ — total payment
- $\kappa_i \in \{P, E\}$ — assigned core type (determined by the auction, not the task)

Since the ISA is shared, a task has no core-type preference — it simply submits a bid $(v_i, l_i)$. The decision to assign to a P-core or E-core is made by the mechanism to maximize social welfare.

A contract is **simple**: once task $i$ receives a core at time $t$, it is guaranteed for $m_i$ quanta with no dependence on future events.

### 3.2 Core Costs

Base cost per quantum:

$$c_P > c_E > 0$$

Ratio $\gamma = c_P / c_E > 1$ reflects the performance difference.

For task $i$ with base length $l_i$ on core type $\kappa$, total contract cost:

$$\text{cost}(i, P) = c_P \cdot l_i, \qquad \text{cost}(i, E) = c_E \cdot \lceil l_i \cdot \sigma \rceil$$

where $\sigma > 1$ is the E-core slowdown factor relative to P-core. The E-core is cheaper per quantum but occupies more quanta. Total cost on E-core may be higher or lower than on P-core depending on $\gamma$ and $\sigma$:

$$\text{cost}(i, E) \lessgtr \text{cost}(i, P) \iff \frac{\lceil l_i \cdot \sigma \rceil}{l_i} \lessgtr \gamma$$

### 3.3 Task Utility

Utility of task $i$ receiving contract $z_i^t = (a_i, m_i, p_i, \kappa_i)$:

$$u_i = \begin{cases} v_i - p_i & \text{if } m_i \geq l_i \text{ and task received a core (full completion)} \\ -p_i & \text{otherwise (task interrupted or did not receive a core)} \end{cases}$$

with budget constraint $p_i \leq B_i$.

---

## 4. Social Cost Function

### 4.1 Social Welfare

Total social welfare as average discounted payoff:

$$W(\pi) = J(\pi; R) = \lim_{T \to \infty} \frac{1}{T} \mathbb{E}\left[\sum_{t=1}^T R(s^t, a^t)\right]$$

where $R = \sum_{j=0}^{n} r_j$ is the total reward.

### 4.2 Social Cost Function

The optimization objective — **Social Cost** — includes:

$$\text{SC}(\pi) = \underbrace{W(\pi)}_{\text{social welfare}} - \underbrace{\lambda_F \cdot \Psi(\pi)}_{\text{fairness penalty}}$$

where:

**Fairness penalty:**
$$\Psi(\pi) = \text{Var}_{i}\!\left[\frac{u_i(\pi)}{v_i}\right]$$

— variance of normalized utilities; penalizes situations where some tasks gain heavily at the expense of others.

Energy differences between P-core and E-core are already captured in quantum costs $c_P > c_E$ and require no separate penalty.

---

## 5. Dynamic VCG Mechanism for the Scheduler

### 5.1 Offline: Full Information (after Leon & Etesami, Def. 2)

With a known MDP, optimal allocation and payments are defined via occupancy measures.

**Optimal allocation policy:**
$$q^* = \arg\max_{q \in \Delta(P)} \langle q, R \rangle$$

**Policy without task $i$:**
$$q^*_{-i} = \arg\max_{q \in \Delta(P)} \langle q, R_{-i} \rangle, \quad R_{-i} = \sum_{j \neq i} r_j$$

**Payment of task $i$ (VCG payment):**

$$p_i^*(s, a) = \underbrace{\langle q^*_{-i}, R_{-i} \rangle}_{\text{optimal welfare without } i} - \underbrace{R_{-i}(s, a)}_{\text{actual welfare without } i \text{ under }(s,a)}$$

Intuition: a task pays for the externality it imposes on others.

### 5.2 Adaptation to Heterogeneous Cores

Key modification: allocation is two-dimensional — the mechanism selects not only "who gets a core" but also "which core type". Define **extended social welfare** accounting for core type:

$$W(s^t) = \max_{a^t} \left[\sum_{i \in \mathcal{N}^t} \left(a_{i,P}^t \cdot \phi_P(v_i, l_i) + a_{i,E}^t \cdot \phi_E(v_i, l_i)\right) + \delta \cdot \mathbb{E}[W(s^{t+1})]\right]$$

where the **effective value** of task $i$ on core type $\kappa$:

$$\phi_P(v_i, l_i) = v_i - c_P \cdot l_i$$

$$\phi_E(v_i, l_i) = v_i - c_E \cdot \lceil l_i \cdot \sigma \rceil$$

P-core executes the task in $l_i$ quanta, E-core in $\lceil l_i \cdot \sigma \rceil$ quanta ($\sigma > 1$). The task does not specify a core preference — the mechanism decides, maximizing social welfare accounting for the opportunity cost of occupying a core for different numbers of quanta.

### 5.3 Virtual Valuations (after Sano, Sec. 5)

For a revenue-maximizing mechanism, define virtual valuation:

$$\varphi(\theta_i) = v_i - \frac{1 - F(v_i | l_i)}{f(v_i | l_i)}$$

Optimal allocation maximizes virtual welfare:

$$R^*(s^t) = \max_{a^t} \left[\sum_{i \in \mathcal{N}^t} \left(a_{i,P}^t \cdot \varphi_P(\theta_i) + a_{i,E}^t \cdot \varphi_E(\theta_i)\right) + \delta \cdot \mathbb{E}[R^*(s^{t+1})]\right]$$

where $\varphi_P(\theta_i) = \varphi(\theta_i) - c_P \cdot l_i$ and $\varphi_E(\theta_i) = \varphi(\theta_i) - c_E \cdot \lceil l_i \cdot \sigma \rceil$.

Under monotone hazard rate ($\lambda_l(v) = f(v|l) / (1 - F(v|l))$ non-decreasing in $v$ and non-increasing in $l$), the optimal policy is monotone and implementable.

---

## 6. Task Bidding Mechanism

### 6.1 Auction Protocol (each quantum $t$)

```
1. Scheduler observes state s^t
2. Each task i ∈ N^t submits bid b_i = (b_i^v, b_i^l):
     b_i^v — declared valuation
     b_i^l — declared length (in P-core quanta)
   Task does NOT specify core type — that is the auction's decision
3. Scheduler solves the allocation problem:
     a^t = argmax Σ_i [a_{i,P} · φ_P(b_i) + a_{i,E} · φ_E(b_i)] + δ·E[W(s^{t+1})]
   where φ_E accounts for slowdown by σ
4. VCG payments p_i^t computed for each winner
5. Budgets updated: B_i ← B_i - p_i^t
6. Tasks with B_i < 0 are rejected (budget exhaustion)
```

### 6.2 VCG Payment Formula (per-quantum)

For task $i$ receiving core type $\kappa$ at time $t$:

$$p_i^t = \underbrace{W_{-i}(s^t)}_{\text{welfare without } i} - \underbrace{\left[W(s^t) - \phi_\kappa(\theta_i)\right]}_{\text{welfare with } i \text{ minus } i\text{'s contribution}}$$

Simplifying:

$$p_i^t = W_{-i}(s^t) - W(s^t) + \phi_\kappa(\theta_i)$$

In the single-unit case (one free core), as in Sano:

$$p_i^t = \phi_\kappa(\hat{\theta}_j) + (\delta^{l_j} - \delta^{l_i}) \cdot \bar{W}$$

where $j$ is the second-ranked task and $\bar{W}$ is the expected future welfare.

### 6.3 Differentiated Pricing: P vs E

For task $i$ with base length $l_i$, define **price per quantum** on each core type:

**P-core** (task occupies $l_i$ quanta):
$$p_P(l) = \frac{\delta - \delta^l}{1 - \delta^l} \cdot \bar{r}_P + \frac{1-\delta}{(1-\delta^l)} \cdot \frac{1}{\lambda(P^{**}(l))}$$

**E-core** (task occupies $l' = \lceil l \cdot \sigma \rceil$ quanta):
$$p_E(l) = \frac{\delta - \delta^{l'}}{1 - \delta^{l'}} \cdot \bar{r}_E + \frac{1-\delta}{(1-\delta^{l'})} \cdot \frac{1}{\lambda(P^{**}(l'))}$$

where $\bar{r}_P > \bar{r}_E$ are average revenues from P-core and E-core respectively.

**Key property:** $p_P(l) > p_E(l)$ per quantum for all $l$ — E-core is cheaper per quantum but the task occupies more quanta. Total payment $P_E(l) = p_E(l) \cdot l'$ may be comparable to $P_P(l) = p_P(l) \cdot l$, creating a non-trivial trade-off for the mechanism.

Under independence of $v_i$ and $l_i$ (Sano Proposition 5), a **long-stay discount** is possible: $p_\kappa(l+1) < p_\kappa(l)$ — tasks with larger length pay less per quantum. This effect is amplified on E-core since $\lceil l \cdot \sigma \rceil$ grows faster than $l$.

---

## 7. Online Learning (Unknown Environment)

### 7.1 IHMDP-VCG Algorithm (adapted from Leon & Etesami)

When task type distributions and the MDP transition kernel are unknown, the scheduler learns online.

**Episodic structure:** learning is divided into episodes $k = 1, 2, \ldots$ of increasing length.

Each episode $k$ consists of:

1. **Mixing phase** (length $d^{[k]} = \frac{\log k}{\alpha S}$): the scheduler applies current policy $\pi^{[k]}$ without collecting payments. Goal: bring the Markov chain to its stationary distribution.

2. **Stationary phase** (length $l^{[k]} = \frac{\max\{4, \sqrt{k}\} \log(|\mathcal{A}||\mathcal{S}|k/\zeta)}{\alpha\delta}$): the scheduler applies $\pi^{[k]}$ and collects payments $\hat{p}^{[k]}$.

### 7.2 Policy Update

At the end of episode $k$, solve $(n+1)$ linear programs:

**Allocation:**
$$\hat{q}^{[k+1]} = \arg\max_{q \in \Delta_\delta(\hat{P}^{[k]})} \langle q, \hat{R}^{[k]} \rangle$$

**Payments (for each task $i$):**
$$\hat{q}^{[k+1]}_{-i} = \arg\max_{q \in \Delta_\delta(\hat{P}^{[k]})} \langle q, \hat{R}^{[k]}_{-i} \rangle$$

$$\hat{p}^{[k+1]}_i(s, a) = \langle \hat{q}^{[k+1]}_{-i}, \hat{R}^{[k]}_{-i} \rangle - \check{R}^{[k]}_{-i}(s, a)$$

where $\hat{R}$ is the UCB estimate and $\check{R}$ is the LCB estimate of reward functions.

### 7.3 Guarantees

For $T \to \infty$, with probability $\geq 1 - O(\zeta)$:

| Metric | Regret upper bound |
|--------|-------------------|
| Social welfare regret | $\tilde{O}(\epsilon T n + T^{2/3} n)$ |
| Seller's regret | $\tilde{O}(\epsilon T n^2 + T^{2/3} n^2)$ |
| Bidders' regret | $\tilde{O}(\epsilon T n^2 + T^{2/3} n^2)$ |

The mechanism asymptotically satisfies efficiency, truthfulness, and individual rationality.

---

## 8. Mechanism Properties

### 8.1 Incentive Compatibility (after Sano, Theorem 1)

The mechanism is incentive-compatible if and only if for each task $i$:

1. $\alpha_i(v_i, l_i)$ is non-decreasing in $v_i$ for fixed $l_i$
2. $\int_0^{v_i} \alpha_i(\nu, l_i) d\nu$ is non-increasing in $l_i$ for fixed $v_i$
3. There exists $\underline{\Pi}_i$, independent of $l_i$, such that:

$$\Pi_i(v_i, l_i) = \underline{\Pi}_i + \int_0^{v_i} \alpha_i(\nu, l_i) d\nu$$

**Consequence:** tasks have no incentive to overstate their valuation or understate their length.

### 8.2 Individual Rationality

$$u_i(\pi^*, p^*) = W(\pi^*; R) - W(\pi^*_{-i}; R_{-i}) \geq 0$$

Each task receives non-negative utility — participation in the auction is beneficial.

### 8.3 Budget Feasibility

Additional constraint (absent in classical VCG):

$$p_i^*(s, a) \leq B_i^t \quad \forall t$$

If the VCG payment exceeds the remaining budget, the task **does not receive a core** in that quantum. This leads to a modified allocation:

$$\tilde{a}^t = \arg\max_{a} \sum_{i: p_i \leq B_i^t} \left[a_{i,P} \cdot \phi_P(\theta_i) + a_{i,E} \cdot \phi_E(\theta_i)\right] + \delta \cdot \mathbb{E}[W(s^{t+1})]$$

---

## 9. Example: Binary Core Types, Single Free Core

Let $K_P = K_E = 1$ and at time $t$ exactly one core of type $\kappa \in \{P, E\}$ is free.

Winning task $i^*$:

$$i^* = \arg\max_{i \in \mathcal{N}^t, B_i^t > 0} \; \phi_\kappa(\theta_i) + \delta^{m_\kappa(l_i)} \bar{W}_\kappa$$

where $m_P(l) = l$, $m_E(l) = \lceil l \cdot \sigma \rceil$ is the actual contract length on core $\kappa$.

Its payment:

$$p_{i^*} = \phi_\kappa^{-1}\!\left(\phi_\kappa(\theta_j) + (\delta^{m_\kappa(l_j)} - \delta^{m_\kappa(l_{i^*})}) \bar{W}_\kappa \;\big|\; l_{i^*}\right)$$

where $j$ is the second-ranked task.

**If both cores are free** (P and E), solve the joint problem:

$$\max \sum_{i} \left[a_{i,P} \cdot \phi_P(\theta_i) + a_{i,E} \cdot \phi_E(\theta_i)\right] + \delta \cdot \mathbb{E}[W(s^{t+1})]$$

$$\text{s.t.} \quad a_{i,P} + a_{i,E} \leq 1, \quad \sum_i a_{i,P} \leq 1, \quad \sum_i a_{i,E} \leq 1, \quad p_i \leq B_i^t$$

Note that $\phi_P(\theta_i) > \phi_E(\theta_i)$ does not always hold: for a task with small $v_i$ and large $l_i$, the E-core may yield greater effective value ($c_E \cdot \lceil l_i \sigma \rceil < c_P \cdot l_i$ when $\sigma < \gamma$). Therefore the optimal strategy is non-trivial — the highest-valuation task goes to the P-core only if the speed gain outweighs the cost difference.

---

> **Theory ends here.** Everything above is the abstract model (system, MDP, contracts, VCG mechanism, online learning, properties). The concrete BPF realisation — parameter values, EEVDF deadline plumbing, budget-ratio routing, work-conservation overrides, and the code↔model mapping — lives in **[`VCG_s4_impl.md`](VCG_s4_impl.md)**.
>
> Changes to §1–§9 (model) require re-derivation; changes to implementation notes do not.

---

## 10. Notation Summary

| Symbol | Meaning |
|--------|---------|
| $K_P, K_E$ | Number of P-cores and E-cores |
| $\mathcal{N}^t$ | Set of active tasks at time $t$ |
| $\theta_i = (v_i, l_i)$ | Task type: valuation and length (shared ISA, no compatibility class) |
| $B_i$ | Budget of task $i$ |
| $c_P, c_E$ | Cost per quantum on P-core / E-core ($c_P > c_E$) |
| $\sigma$ | E-core slowdown factor ($\sigma = \eta_P / \eta_E > 1$) |
| $\gamma$ | Cost ratio ($\gamma = c_P / c_E > 1$) |
| $\phi_\kappa(\theta_i)$ | Effective value of task $i$ on core type $\kappa$ |
| $\varphi(\theta_i)$ | Virtual valuation (Myerson) |
| $p_i^*$ | VCG payment of task $i$ |
| $W(\pi)$ | Social welfare under policy $\pi$ |
| $\text{SC}(\pi)$ | Social cost function |
| $q \in \Delta(P)$ | Occupancy measure |
| $m_\kappa(l)$ | Actual contract length: $m_P(l) = l$, $m_E(l) = \lceil l \sigma \rceil$ |
| $\delta \in (0,1)$ | Discount factor |
| $\alpha$ | MDP ergodicity parameter |
| $\rho_i = B_i / B_i^{\max}$ | Budget ratio (proxy for "bursty vs CPU-bound") — see `VCG_s4_impl.md` §I2 |
| $l_{ns}$ | EWMA of task activation length (ns) — proxy for $l_i$ — see `VCG_s4_impl.md` §I1 |
