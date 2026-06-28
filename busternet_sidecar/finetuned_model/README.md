# Model Fine-Tuning Results: COVERAGE Dataset

This document summarizes the fine-tuning experiment results for the Digital Image Forgery Detection (DIFD) tool. The experiment evaluates the model's performance on the COVERAGE dataset, comparing baseline metrics against a model with 10 fine-tuned terminal layers over 50 epochs. 

## 📊 Performance Comparison

The following table highlights the model's performance improvements and trade-offs after fine-tuning. Primary test metrics are calculated using the validation-selected threshold.

| Metric | Baseline | Fine-Tuned |
| :--- | :--- | :--- |
| **Validation-Selected Threshold** | 0.55 | 0.70 |
| **Image-level F1** | 0.6500 | 0.6818 |
| **Test Pixel AUC** | 0.8414 | 0.8451 |
| **Test Pixel F1** | 0.4939 | 0.4900 |
| **Test Pixel IoU** | 0.3280 | 0.3245 |
| **Original FP Pixel Rate** | 0.1153 | 0.1598 |

## 📁 Dataset Specifications

The experiment utilized the COVERAGE dataset with the following configuration and splits:

* **Split Seed:** 42
* **Total COVERAGE IDs:** 100
* **Total Images:** 200 (including negative controls)
* **Total Masks:** 300
* **Total Labels:** 4
* **Train IDs:** 70
* **Validation IDs:** 15
* **Test IDs:** 15

## ⚙️ Fine-Tuning Parameters

* **Epochs Requested:** 50
* **Trainable Last Layers:** 10

## 📝 Experiment Notes

> * **Thresholding:** Primary test metrics use the validation-selected threshold. Metrics for a fixed `0.5` threshold are also available in the associated JSON export file.
> * **Negative Controls:** Original (unforged) images are utilized as negative controls and are paired with all-zero masks.