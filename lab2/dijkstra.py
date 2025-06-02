
import heapq

class Dijkistra:
	
	def __init__(self, graph,source,destination):
	
		self.visited=set()
		
		self.previous_node={node: None for node in graph}
	
		self.unvisited={node: float('inf') for node in graph}
		
		self.unvisited[source] = 0
		
		self.hopes_heap = [(0,source)]
		
		while self.hopes_heap:
			current_distance, current_node =  heapq.heappop(self.hopes_heap)
			
			if current_distance > self.unvisited[current_node] or current_node in self.visited:
				continue
				
			self.visited.add(current_node)
			
			for neighbour_node in graph[current_node]:
				new_distance = current_distance + 1
				
				if new_distance < self.unvisited[neighbour_node]:
					self.unvisited[neighbour_node] = new_distance
					self.previous_node[neighbour_node] = current_node
					heapq.heappush(self.hopes_heap, (new_distance, neighbour_node))
		

		path = []
		current = destination
		
		while current is not None:
			path.append(current)
			current = self.previous_node[current]
		print(f"{source} = > {destination}")
		print(path)
		 	
		
		
		
			
