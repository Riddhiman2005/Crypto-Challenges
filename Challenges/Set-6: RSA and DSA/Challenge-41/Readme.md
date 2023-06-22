

We know that the RSA ciphertext $c$ and message $m$ have this form:

```math
\begin{matrix}
c\equiv m^p\bmod n
\\
m\equiv c^{d}\bmod n
\end{matrix}
```

Here's the proof that the message's form is correct:

```math
\begin{matrix}
m\equiv c^{d}\equiv (m^{p})^{d}\equiv m^{pd}\equiv m\bmod n
\\
(d\equiv p^{-1}\bmod n\Rightarrow pd\equiv 1 \bmod n)
\end{matrix}
```

We now construct our new ciphertext $c^{'}$ with a random number $s$ such that $s>1\bmod n$:

```math
c^{'}\equiv s^{p}c\bmod n
```

After submitting our new ciphertext $c^{'}$ to the server, we get the new plaintext $m^{'}$:

```math
m^{'}\equiv (c^{'})^{d}\equiv (s^{p}c)^{d}\equiv (s^{p}m^{p})^{d}\equiv sm\bmod n
```

You may now notice, that there's the original plaintext $m$ on the right side of the equation. To isolate it, we need to multiply both sides with the multiplicative inverse $s^{-1}$ of $s$:

```math
ms^{-1}\equiv sms^{-1}\equiv m\bmod n\Rightarrow \underline{ms^{-1}\equiv m\bmod n}
```

As you can see, we successfully recovered the original text $m$.
