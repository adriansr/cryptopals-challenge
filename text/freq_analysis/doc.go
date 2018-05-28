// Package freq_analysis contains tools to analyze the frequency of characters
// in text.
package freq_analysis

type FrequencyMap map[byte]float64

func (fm FrequencyMap) FrequencyFor(value byte) float64 {
	if res, ok := fm[value]; ok {
		return res
	}
	return 0.0
}
