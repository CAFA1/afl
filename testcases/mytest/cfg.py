# import angr
# from angrutils import *
# def cfgfastpng(filename):
# 	proj = angr.Project(filename,load_options={"auto_load_libs":False})
# 	print("----------static-----------")
# 	cfg = proj.analyses.CFGFast()
# 	plot_cfg(cfg, filename, asminst=True, remove_imports=True, remove_path_terminator=True)
# cfgfastpng("./mytest")

#! /usr/bin/env python
 
import angr
from angrutils import plot_cfg

def analyze(b, addr, name=None):
	start_state = b.factory.blank_state(addr=addr)
	start_state.stack_push(0x0)
	#import IPython
	#IPython.embed()
	cfg = b.analyses.CFGFast()
	print("This is the graph:", cfg.graph)
	print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
	# this grabs *any* node at a given location:
	entry_node = cfg.get_any_node(b.entry)

	# on the other hand, this grabs all of the nodes
	print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(b.entry)))

	# we can also look up predecessors and successors
	print("Predecessors of the entry point:", entry_node.predecessors)
	print("Successors of the entry point:", entry_node.successors)
	print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])
 
if __name__ == "__main__":
	proj = angr.Project("./mytest", load_options={'auto_load_libs':False})
	main = proj.loader.main_object.get_symbol("main")
	analyze(proj, main.rebased_addr, "mytest")