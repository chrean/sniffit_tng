all: sniffit_tng

sniffit_tng: sniffit_tng.o 
	gcc sniffit_tng.o -o sniffit_tng