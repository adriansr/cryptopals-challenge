package freq_analysis

func ScoreFrequencies(data []byte, fMap FrequencyMap) (result float64) {
	for _,b := range data {
		result += fMap.FrequencyFor(b)
	}
	return result
}
