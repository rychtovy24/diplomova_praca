import ontospy
from ontospy.ontodocs.viz.viz_html_single import *

g = ontospy.Ontospy("http://cohere.open.ac.uk/ontology/cohere.owl#")

v = HTMLVisualizer(g) # => instantiate the visualization object
v.build() # => render visualization. You can pass an 'output_path' parameter too
v.preview() # => open in browser
