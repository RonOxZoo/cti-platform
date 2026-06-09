-- Add full-text search index on intelligence_items
ALTER TABLE intelligence_items
ADD COLUMN IF NOT EXISTS search_vector tsvector;

UPDATE intelligence_items
SET search_vector = to_tsvector('english',
  coalesce(title_en, '') || ' ' ||
  coalesce(summary_en, '') || ' ' ||
  coalesce(array_to_string(categories, ' '), '')
);

CREATE INDEX IF NOT EXISTS intelligence_items_fts_idx
ON intelligence_items USING gin(search_vector);

-- Auto-update search_vector on insert/update
CREATE OR REPLACE FUNCTION update_search_vector()
RETURNS trigger AS $$
BEGIN
  NEW.search_vector := to_tsvector('english',
    coalesce(NEW.title_en, '') || ' ' ||
    coalesce(NEW.summary_en, '') || ' ' ||
    coalesce(array_to_string(NEW.categories, ' '), '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS intelligence_items_search_vector_update ON intelligence_items;

CREATE TRIGGER intelligence_items_search_vector_update
BEFORE INSERT OR UPDATE ON intelligence_items
FOR EACH ROW EXECUTE FUNCTION update_search_vector();
