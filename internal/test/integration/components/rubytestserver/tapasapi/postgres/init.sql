CREATE TABLE restaurants (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  neighborhood VARCHAR(255) NOT NULL,
  food_type VARCHAR(255) NOT NULL,
  description TEXT,
  address VARCHAR(255),
  price_range VARCHAR(10),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE reviews (
  id SERIAL PRIMARY KEY,
  restaurant_id INTEGER NOT NULL REFERENCES restaurants(id) ON DELETE CASCADE,
  author VARCHAR(255) NOT NULL,
  rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
  comment TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_restaurants_neighborhood ON restaurants (neighborhood);
CREATE INDEX idx_restaurants_food_type ON restaurants (food_type);
CREATE INDEX idx_reviews_restaurant_id ON reviews (restaurant_id);

INSERT INTO restaurants (name, neighborhood, food_type, description, address, price_range) VALUES
('Quimet & Quimet', 'Poble Sec', 'Traditional Tapas', 'Tiny, legendary tapas bar famous for its montaditos and huge wine selection.', 'Carrer del Poeta Cabanyes 25, Poble Sec', '€€'),
('El Xampanyet', 'El Born', 'Traditional Tapas', 'Old-school cava and tapas bar serving anchovies, cured meats and tortilla.', 'Carrer de Montcada 22, El Born', '€'),
('Bar Cañete', 'El Raval', 'Seafood Tapas', 'Counter-seating classic with fresh seafood and Andalusian-style fried fish.', 'Carrer de la Unio 17, El Raval', '€€€'),
('Cal Pep', 'El Born', 'Seafood Tapas', 'Bustling counter bar known for fried fish, seafood and no reservations.', 'Placa de les Olles 8, El Born', '€€€'),
('Bormuth', 'El Born', 'Modern Tapas', 'Trendy spot for patatas bravas and creative pinchos with vermouth on tap.', 'Carrer del Rec 31, El Born', '€€'),
('Bar Mut', 'Eixample', 'Gourmet Tapas', 'Upscale tapas bar with market-driven small plates and an excellent wine list.', 'Pau Claris 192, Eixample', '€€€€'),
('La Cova Fumada', 'Poble Sec', 'Traditional Tapas', 'Birthplace of the bomba, this no-frills bar serves classic working-class tapas.', 'Carrer del Baluard 56, Poble Sec', '€'),
('Tapas 24', 'Eixample', 'Modern Tapas', 'Carles Abellan gourmet take on classic tapas like the McFoie burger.', 'Diputacio 269, Eixample', '€€€'),
('Bar Pinotxo', 'La Boqueria', 'Market Tapas', 'Iconic counter inside La Boqueria market serving chickpeas with morcilla.', 'La Boqueria Market, Ciutat Vella', '€€'),
('Euskal Etxea', 'El Born', 'Basque Tapas', 'Basque cultural center bar famous for pintxos with toothpicks on the counter.', 'Placeta Montcada 1, El Born', '€€'),
('Bodega Biarritz', 'Eixample', 'Traditional Tapas', 'Family-run bodega with vermouth, canned seafood and homestyle tapas.', 'Carrer de Balmes 6, Eixample', '€€'),
('Vinitus', 'Eixample', 'Modern Tapas', 'Cozy wine and tapas bar popular with tourists near Passeig de Gracia.', 'Carrer del Bruc 184, Eixample', '€€'),
('El Vaso de Oro', 'La Barceloneta', 'Beer Hall Tapas', 'Narrow beer-hall bar loved for its own-brewed beer and solomillo skewers.', 'Carrer de Balboa 6, La Barceloneta', '€€'),
('Can Paixano (La Xampanyeria)', 'La Barceloneta', 'Cava Tapas', 'Standing-room-only cava bar serving cheap bubbly with tiny sandwiches.', 'Carrer de la Reina Cristina 7, La Barceloneta', '€'),
('Bar del Pla', 'El Born', 'Modern Tapas', 'Relaxed neighborhood bar mixing traditional and modern Catalan tapas.', 'Carrer de Montcada 2, El Born', '€€');

INSERT INTO reviews (restaurant_id, author, rating, comment) VALUES
(1, 'Marta G.', 5, 'The montaditos here are unbeatable, always packed but worth the wait.'),
(1, 'Jordi P.', 4, 'Great vermouth selection, a bit cramped but full of character.'),
(2, 'Laura S.', 5, 'Loved the cava and anchovies, very authentic old Barcelona vibe.'),
(3, 'Anna R.', 5, 'Best fried fish I have had in the city, ask for the daily specials.'),
(4, 'Marc T.', 4, 'Chaotic and loud but the seafood is fantastic, go early.'),
(5, 'Nuria V.', 4, 'Great patatas bravas, good spot for a casual night with friends.'),
(6, 'David L.', 5, 'Pricier but the quality of ingredients really shows.'),
(7, 'Elena F.', 5, 'The original bomba, a must for any tapas tour of Poble Sec.'),
(8, 'Sergi M.', 4, 'Creative dishes, the McFoie burger is a fun twist.'),
(9, 'Cristina B.', 5, 'Grab a stool early, the chickpeas with morcilla are legendary.'),
(10, 'Pau A.', 4, 'Fun pintxo bar, self-service honor system with toothpicks.'),
(12, 'Irene C.', 3, 'Solid tapas but very touristy and can be noisy.');
