# ECDAT Quantum Risk Model — Feature-Group Ablation Analysis

Inference-time ablation evaluates the performance impact when replacing specific feature groups with training-distribution baseline defaults without retraining.

| Experiment | Ablated Group | Transformed Dims | Macro F1 | Accuracy | F1 Drop | Recall LOW | Recall MED | Recall HIGH | Recall CRIT |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Baseline (All Features) | None | 0 | 0.9320 | 0.9449 | 0.0000 | 0.9162 | 0.9469 | 0.9747 | 0.8770 |
| Ablate: A. Cryptographic Primitives | A. Cryptographic Primitives | 97 | 0.8935 | 0.9170 | 0.0385 | 0.8663 | 0.9528 | 0.9483 | 0.7517 |
| Ablate: B. Business Context | B. Business Context | 11 | 0.7061 | 0.7873 | 0.2260 | 0.2193 | 0.9329 | 0.9669 | 0.6872 |
| Ablate: C. Exposure Features | C. Exposure Features | 19 | 0.8547 | 0.8864 | 0.0774 | 0.9330 | 0.8256 | 0.9874 | 0.6196 |
| Ablate: D. Migration & Agility | D. Migration & Agility | 4 | 0.9015 | 0.9235 | 0.0305 | 0.8991 | 0.9231 | 0.9765 | 0.7608 |
| Ablate: E. HNDL & Quantum Timeline | E. HNDL & Quantum Timeline | 9 | 0.4518 | 0.5658 | 0.4802 | 0.7273 | 0.9560 | 0.2242 | 0.0159 |
| Ablate: F. Operational & Dependencies | F. Operational & Dependencies | 11 | 0.9219 | 0.9361 | 0.0101 | 0.8656 | 0.9562 | 0.9636 | 0.8945 |
