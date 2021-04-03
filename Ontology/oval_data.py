import xml.etree.ElementTree as ET
from rdflib.namespace import RDF, RDFS
from rdflib import URIRef, BNode, Literal, Namespace
from rdflib import Graph

MAIN_IRI = "http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology"

FAMILY_OWL = URIRef(MAIN_IRI + "#Family")
PRODUCT_OWL = URIRef(MAIN_IRI + "#Product")
PLATFORM_OWL = URIRef(MAIN_IRI + "#Platform")
OVAL_OWL = URIRef("https://oval.mitre.org/language/version5.11/OVAL")
OVAL_has_description = URIRef(MAIN_IRI + "#hasDescription")
OVAL_has_reference = URIRef(MAIN_IRI + "#hasReference")
OVAL_has_title = URIRef(MAIN_IRI + "#hasTitle")
OVAL_affected_family = URIRef(MAIN_IRI + "#affectedFamily")
OVAL_affected_platform = URIRef(MAIN_IRI + "#affectedPlatform")
OVAL_affected_product = URIRef(MAIN_IRI + "#affectedProduct")

REFERENCE_OWL = URIRef(MAIN_IRI + "#Reference")
REFERENCE_has_description = OVAL_has_description
REFERENCE_has_ref_id = URIRef(MAIN_IRI + "#hasRefID")
REFERENCE_has_source = URIRef(MAIN_IRI + "#hasSource")

CVE_NAMESPACE = Namespace("https://cve.mitre.org/about/terminology.html#")


CVE_IRI = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
FAMILY_IRI = MAIN_IRI + "/family#"
PRODUCT_IRI = MAIN_IRI + "/product#"
PLATFORM_IRI = MAIN_IRI + "/platform#"

families = {}
platforms = {}
products = {}

class Family:
    def __init__(self, family):
        self.iri = URIRef(FAMILY_IRI + family.attrib['family'].replace(' ', '_'))
        self.label = family.attrib['family']
        self.platforms = []
        families[family.attrib['family']] = self

    def add_platform(self, platform):
        for i in self.platforms:
            if i.iri == platform.iri:
                return
        self.platforms.append(platform)

    def write(self, graph):
        graph.add( (self.iri, RDF.type, FAMILY_OWL) )
        graph.add( (self.iri, RDFS.label, Literal(self.label)) )


class Platform:
    def __init__(self, platform):
        self.iri = URIRef(PLATFORM_IRI + platform.text.replace(' ', '_'))
        self.label = platform.text
        platforms[platform.text] = self

    def write(self, graph):
        graph.add( (self.iri, RDF.type, PLATFORM_OWL) )
        graph.add( (self.iri, RDFS.label, Literal(self.label)) )

class Product:
    def __init__(self, product):
        self.iri = URIRef(PRODUCT_IRI + product.text.replace(' ', '_'))
        self.label = product.text
        products[product.text] = self

    def write(self, graph):
        graph.add( (self.iri, RDF.type, PRODUCT_OWL) )
        graph.add( (self.iri, RDFS.label, Literal(self.label)) )

class Reference:
    def __init__(self, reference):
        self.iri = URIRef(reference.attrib['ref_url'])
        self.ref_id = reference.attrib['ref_id']
        self.source = reference.attrib['source']


class OVAL:
    def __init__(self, definition):
        self.id = definition.attrib['id']
        print(self.id)
        self.iri = URIRef(self.id)
        self.label = ''
        self.description = ''
        self.references = []
        self.family = ''
        self.platforms = []
        self.products = []
        for elem in definition.iter():
            if elem.tag.find('}title') >= 0:
                self.label = elem.text

            elif elem.tag.find('}affected') >= 0:
                if elem.attrib['family'] in families:
                    self.family = families[elem.attrib['family']]
                else:
                    self.family = Family(elem)
            elif elem.tag.find('}description') >= 0:
                self.description = elem.text

            elif elem.tag.find('}platform') >= 0:
                if elem.text in platforms:
                    self.platforms.append(platforms[elem.text])
                else:
                    self.platforms.append(Platform(elem))
                self.family.add_platform(platforms[elem.text])

            elif elem.tag.find('}product') >= 0:
                if elem.text in products:
                    self.products.append(products[elem.text])
                else:
                    self.products.append(Product(elem))

            elif elem.tag.find('}reference') >= 0:
                if 'ref_url' in elem.attrib:
                    self.references.append(Reference(elem))

            elif elem.tag.find('}affected') >= 0:
                self.product = Product(elem)
        

    def write_OVAL(self, graph):
        graph.add( (self.iri, RDF.type, OVAL_OWL) )
        graph.add( (self.iri, RDFS.label, Literal(self.label)) )
        graph.add( (self.iri, OVAL_has_description, Literal(self.description)) )
        graph.add( (self.iri, OVAL_has_title, Literal(self.label)) )
        graph.add( (self.iri, OVAL_affected_family, self.family.iri) )
        for product in self.products:
            graph.add( (self.iri, OVAL_affected_product, product.iri) )
        for platform in self.platforms:
            graph.add( (self.iri, OVAL_affected_platform, platform.iri) )
        


    


tree = ET.parse('oval_data.xml')
root = tree.getroot()
oval_dic = {}
count = 0
for child in root:
    if child.tag.find('}definitions') < 0:
        continue
    for definition in child:
        if definition.tag.find('}definition') < 0:
            continue
        if definition.attrib['class'] == 'inventory':
            continue
        oval_dic[definition.attrib['id']] = OVAL(definition)
        count += 1
        #if count > 100:
            #break

print(count)

graph = Graph()
graph.bind('cve', CVE_NAMESPACE)

for key in families:
    families[key].write(graph)

for key in products:
    products[key].write(graph)
    
for key in platforms:
    platforms[key].write(graph)

for key in oval_dic:
    oval_dic[key].write_OVAL(graph)


    

with open('oval_generate_data.rdf', 'w', encoding="utf-8") as f:
    print(graph.serialize(format="turtle").decode("utf-8"), file=f)

    

