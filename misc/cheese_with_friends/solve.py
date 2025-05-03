with open('source.txt', 'r') as f:
	source = f.read()

source = source.replace('church', '___')
source = source.replace('*', '   ')
source = source.replace('%', '_')
source = source.replace('$', ' ')
source = source.replace('&', '|')

with open('solve.txt', 'w') as f:
	f.write(source)

# srdnlen{R0t73n_5H0r7Cu75}
